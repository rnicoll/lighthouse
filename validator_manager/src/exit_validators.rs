use super::common::*;
use crate::DumpConfig;
use clap::{Arg, ArgAction, ArgMatches, Command};
use clap_utils::FLAG_HEADER;
use eth2::{lighthouse_vc::std_types::ImportKeystoreStatus, SensitiveUrl};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

pub const CMD: &str = "exit";
pub const VALIDATORS_FILE_FLAG: &str = "validators-file";
pub const VC_URL_FLAG: &str = "vc-url";
pub const VC_TOKEN_FLAG: &str = "vc-token";

pub fn cli_app() -> Command {
    Command::new(CMD)
        .about(
            "Build and sign a voluntary exit message for validators. The validators \
                are defined in a JSON file which can be generated using the \"create-validators\" \
                command.",
        )
        .arg(
            Arg::new("help")
                .long("help")
                .short('h')
                .help("Prints help information")
                .action(ArgAction::HelpLong)
                .display_order(0)
                .help_heading(FLAG_HEADER),
        )
        .arg(
            Arg::new(VALIDATORS_FILE_FLAG)
                .long(VALIDATORS_FILE_FLAG)
                .value_name("PATH_TO_JSON_FILE")
                .help(
                    "The path to a JSON file containing a list of validators to be \
                    exited to the validator client. This file is usually named \
                    \"validators.json\".",
                )
                .required(true)
                .action(ArgAction::Set)
                .display_order(0),
        )
        .arg(
            Arg::new(VC_URL_FLAG)
                .long(VC_URL_FLAG)
                .value_name("HTTP_ADDRESS")
                .help(
                    "A HTTP(S) address of a validator client using the keymanager-API.",
                )
                .default_value("http://localhost:5062")
                .requires(VC_TOKEN_FLAG)
                .action(ArgAction::Set)
                .display_order(0),
        )
        .arg(
            Arg::new(VC_TOKEN_FLAG)
                .long(VC_TOKEN_FLAG)
                .value_name("PATH")
                .help("The file containing a token required by the validator client.")
                .action(ArgAction::Set)
                .display_order(0),
        )
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ExitValidator {
    pub validators_file_path: PathBuf,
    pub vc_url: SensitiveUrl,
    pub vc_token_path: PathBuf,
}

impl ExitValidator {
    fn from_cli(matches: &ArgMatches) -> Result<Self, String> {
        Ok(Self {
            validators_file_path: clap_utils::parse_required(matches, VALIDATORS_FILE_FLAG)?,
            vc_url: clap_utils::parse_required(matches, VC_URL_FLAG)?,
            vc_token_path: clap_utils::parse_required(matches, VC_TOKEN_FLAG)?,
        })
    }
}

pub async fn cli_run(matches: &ArgMatches, dump_config: DumpConfig) -> Result<(), String> {
    let config = ExitValidator::from_cli(matches)?;
    if dump_config.should_exit_early(&config)? {
        Ok(())
    } else {
        run(config).await
    }
}

async fn run<'a>(config: ExitValidator) -> Result<(), String> {
    let ExitValidator {
        validators_file_path,
        vc_url,
        vc_token_path,
    } = config;

    if !validators_file_path.exists() {
        return Err(format!("Unable to find file at {:?}", validators_file_path));
    }

    let validators_file = fs::OpenOptions::new()
        .read(true)
        .create(false)
        .open(&validators_file_path)
        .map_err(|e| format!("Unable to open {:?}: {:?}", validators_file_path, e))?;
    let validators: Vec<ValidatorSpecification> = serde_json::from_reader(&validators_file)
        .map_err(|e| {
            format!(
                "Unable to parse JSON in {:?}: {:?}",
                validators_file_path, e
            )
        })?;

    let count = validators.len();

    let (http_client, _keystores) = vc_http_client(vc_url.clone(), &vc_token_path).await?;

    eprintln!(
        "Starting to submit {} validators to VC, each validator may take several seconds",
        count
    );

    for (i, validator) in validators.into_iter().enumerate() {
        match validator.upload(&http_client).await {
            Ok(status) => {
                match status.status {
                    ImportKeystoreStatus::Imported => {
                        eprintln!("Uploaded keystore {} of {} to the VC", i + 1, count)
                    }
                    ImportKeystoreStatus::Duplicate => {
                        if ignore_duplicates {
                            eprintln!("Re-uploaded keystore {} of {} to the VC", i + 1, count)
                        } else {
                            eprintln!(
                                "Keystore {} of {} was uploaded to the VC, but it was a duplicate. \
                                Exiting now, use --{} to allow duplicates.",
                                i + 1, count, IGNORE_DUPLICATES_FLAG
                            );
                            return Err(DETECTED_DUPLICATE_MESSAGE.to_string());
                        }
                    }
                    ImportKeystoreStatus::Error => {
                        eprintln!(
                            "Upload of keystore {} of {} failed with message: {:?}. \
                                A potential solution is run this command again \
                                using the --{} flag, however care should be taken to ensure \
                                that there are no duplicate deposits submitted.",
                            i + 1,
                            count,
                            status.message,
                            IGNORE_DUPLICATES_FLAG
                        );
                        return Err(format!("Upload failed with {:?}", status.message));
                    }
                }
            }
            e @ Err(UploadError::InvalidPublicKey) => {
                eprintln!("Validator {} has an invalid public key", i);
                return Err(format!("{:?}", e));
            }
            ref e @ Err(UploadError::DuplicateValidator(voting_public_key)) => {
                eprintln!(
                    "Duplicate validator {:?} already exists on the destination validator client. \
                    This may indicate that some validators are running in two places at once, which \
                    can lead to slashing. If you are certain that there is no risk, add the --{} flag.",
                    voting_public_key, IGNORE_DUPLICATES_FLAG
                );
                return Err(format!("{:?}", e));
            }
            Err(UploadError::FailedToListKeys(e)) => {
                eprintln!(
                    "Failed to list keystores. Some keys may have been exited whilst \
                    others may not have been exited. A potential solution is run this command again \
                    using the --{} flag, however care should be taken to ensure that there are no \
                    duplicate deposits submitted.",
                    IGNORE_DUPLICATES_FLAG
                );
                return Err(format!("{:?}", e));
            }
            Err(UploadError::KeyUploadFailed(e)) => {
                eprintln!(
                    "Failed to upload keystore. Some keys may have been exited whilst \
                    others may not have been exited. A potential solution is run this command again \
                    using the --{} flag, however care should be taken to ensure that there are no \
                    duplicate deposits submitted.",
                    IGNORE_DUPLICATES_FLAG
                );
                return Err(format!("{:?}", e));
            }
            Err(UploadError::IncorrectStatusCount(count)) => {
                eprintln!(
                    "Keystore was uploaded, however the validator client returned an invalid response. \
                    A potential solution is run this command again using the --{} flag, however care \
                    should be taken to ensure that there are no duplicate deposits submitted.",
                    IGNORE_DUPLICATES_FLAG
                );
                return Err(format!(
                    "Invalid status count in exit response: {}",
                    count
                ));
            }
            Err(UploadError::FeeRecipientUpdateFailed(e)) => {
                eprintln!(
                    "Failed to set fee recipient for validator {}. This value may need \
                    to be set manually. Continuing with other validators. Error was {:?}",
                    i, e
                );
            }
            Err(UploadError::PatchValidatorFailed(e)) => {
                eprintln!(
                    "Failed to set some values on validator {} (e.g., builder, enabled or gas limit. \
                    These values value may need to be set manually. Continuing with other validators. \
                    Error was {:?}",
                    i, e
                );
            }
        }
    }

    Ok(())
}
