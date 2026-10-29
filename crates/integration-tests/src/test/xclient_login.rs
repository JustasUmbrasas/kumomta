use crate::kumod::DaemonWithMaildirOptions;
use anyhow::Context;
use rfc5321::parser::{Command, XClientParameter};

/// XCLIENT LOGIN marks the session as authenticated with the asserted
/// identity: the ADDR switch still happens, and a later AUTH is refused as
/// "already authenticated", exactly as after a real AUTH exchange.
#[tokio::test]
async fn xclient_login_authenticates_session() -> anyhow::Result<()> {
    let daemon = DaemonWithMaildirOptions::new()
        .start()
        .await
        .context("DaemonWithMaildir::start")?;

    let mut client = daemon.smtp_client().await.context("make smtp_client")?;

    let props = client.ehlo_lhlo("there", false).await?;
    let xclient = props
        .get("XCLIENT")
        .and_then(|p| p.param.clone())
        .unwrap_or_default();
    assert!(
        xclient.contains("LOGIN"),
        "LOGIN not advertised: {xclient:?}"
    );

    let result = client
        .send_command(&Command::XClient(vec![
            XClientParameter {
                name: "ADDR".to_string(),
                value: "42.42.42.42".to_string(),
            },
            XClientParameter {
                name: "LOGIN".to_string(),
                value: "daniel".to_string(),
            },
        ]))
        .await?;
    k9::assert_equal!(result.code, 220);

    // The listener only allows XCLIENT from loopback; the session now looks like
    // 42.42.42.42, so a second XCLIENT is refused, but the identity sticks.
    let again = client
        .send_command(&Command::Auth {
            sasl_mech: "PLAIN".to_string(),
            initial_response: None,
        })
        .await?;
    k9::assert_equal!(again.code, 503);
    k9::assert_equal!(again.content, "5.5.1 AUTH me once, can't get authed again!");

    daemon.stop_both().await?;
    Ok(())
}

/// Postfix sends LOGIN=[UNAVAILABLE] for an unauthenticated client; that must
/// not authenticate the session.
#[tokio::test]
async fn xclient_login_unavailable_is_not_an_identity() -> anyhow::Result<()> {
    let daemon = DaemonWithMaildirOptions::new()
        .start()
        .await
        .context("DaemonWithMaildir::start")?;

    let mut client = daemon.smtp_client().await.context("make smtp_client")?;

    let result = client
        .send_command(&Command::XClient(vec![XClientParameter {
            name: "LOGIN".to_string(),
            value: "[UNAVAILABLE]".to_string(),
        }]))
        .await?;
    k9::assert_equal!(result.code, 220);

    // Still unauthenticated: AUTH is refused for lack of TLS, not as a repeat.
    let auth = client
        .send_command(&Command::Auth {
            sasl_mech: "PLAIN".to_string(),
            initial_response: None,
        })
        .await?;
    k9::assert_equal!(auth.code, 524);

    daemon.stop_both().await?;
    Ok(())
}
