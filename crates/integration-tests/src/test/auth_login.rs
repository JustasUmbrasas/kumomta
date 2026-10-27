use crate::kumod::DaemonWithMaildir;
use rfc5321::parser::Command;

// base64 of "daniel", "tiger" and "wrong"
const USER_B64: &str = "ZGFuaWVs";
const PASS_B64: &str = "dGlnZXI=";
const WRONG_B64: &str = "d3Jvbmc=";

/// AUTH LOGIN is the two-prompt exchange: "Username:" then "Password:", each
/// base64. The sink permits AUTH in the clear (allow_auth_without_tls), so the
/// exchange runs without STARTTLS and lands in the same smtp_server_auth_plain
/// handler as AUTH PLAIN.
#[tokio::test]
async fn auth_login_two_prompts() -> anyhow::Result<()> {
    let daemon = DaemonWithMaildir::start_with_env(vec![]).await?;
    let mut client = daemon.sink.smtp_client("localhost").await?;

    let props = client.ehlo_lhlo("there", false).await?;
    let auth = props
        .get("AUTH")
        .and_then(|p| p.param.clone())
        .unwrap_or_default();
    assert!(
        auth.contains("LOGIN"),
        "AUTH LOGIN not advertised: {auth:?}"
    );

    let prompt = client
        .send_command(&Command::Auth {
            sasl_mech: "LOGIN".to_string(),
            initial_response: None,
        })
        .await?;
    k9::assert_equal!(prompt.code, 334);
    k9::assert_equal!(prompt.content, "VXNlcm5hbWU6");

    let prompt = client
        .send_command(&Command::Unknown(USER_B64.into()))
        .await?;
    k9::assert_equal!(prompt.code, 334);
    k9::assert_equal!(prompt.content, "UGFzc3dvcmQ6");

    let result = client
        .send_command(&Command::Unknown(PASS_B64.into()))
        .await?;
    k9::assert_equal!(result.code, 235);

    // Authenticated once; a second attempt is refused like after AUTH PLAIN.
    let again = client
        .send_command(&Command::Auth {
            sasl_mech: "PLAIN".to_string(),
            initial_response: None,
        })
        .await?;
    k9::assert_equal!(again.code, 503);

    daemon.stop_both().await?;
    Ok(())
}

/// The username may ride on the AUTH line as the initial response; a wrong
/// password is a 535 exactly as for PLAIN.
#[tokio::test]
async fn auth_login_initial_response_wrong_password() -> anyhow::Result<()> {
    let daemon = DaemonWithMaildir::start_with_env(vec![]).await?;
    let mut client = daemon.sink.smtp_client("localhost").await?;

    let prompt = client
        .send_command(&Command::Auth {
            sasl_mech: "LOGIN".to_string(),
            initial_response: Some(USER_B64.to_string()),
        })
        .await?;
    k9::assert_equal!(prompt.code, 334);
    k9::assert_equal!(prompt.content, "UGFzc3dvcmQ6");

    let result = client
        .send_command(&Command::Unknown(WRONG_B64.into()))
        .await?;
    k9::assert_equal!(result.code, 535);

    daemon.stop_both().await?;
    Ok(())
}

/// Without allow_auth_without_tls (the source listener), AUTH in the clear is
/// still refused and not advertised.
#[tokio::test]
async fn auth_requires_tls_by_default() -> anyhow::Result<()> {
    let daemon = DaemonWithMaildir::start_with_env(vec![]).await?;
    let mut client = daemon.smtp_client().await?;

    let props = client.ehlo_lhlo("there", false).await?;
    assert!(
        props.get("AUTH").is_none(),
        "AUTH advertised in the clear: {props:#?}"
    );

    let result = client
        .send_command(&Command::Auth {
            sasl_mech: "LOGIN".to_string(),
            initial_response: Some(USER_B64.to_string()),
        })
        .await?;
    k9::assert_equal!(result.code, 524);

    daemon.stop_both().await?;
    Ok(())
}
