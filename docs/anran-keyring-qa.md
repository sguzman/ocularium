# ANRAN keyring QA (offline; no camera or account login)

This is a one-time check of local credential recall, **not** a test of
ANRAN cloud authentication or video. It does not contact the vendor.
Do not click **Connect once and count devices** during this test.
The phone app should not be logged out by the steps below.

## Procedure

1. In the **existing Ocularium checkout**, run `git pull` and
   `cargo run --release`. Do not clone a new checkout or change branches.
   If either command fails, stop and send its error; do not troubleshoot.
2. Open **ANRAN account discovery (experimental)** and set
   **App where this camera is paired** to **ANRAN app**.
3. Check **I verified this camera is listed in my ANRAN app account**
   to expose the account inputs. This checkbox does not submit a login.
4. For the previously tested US-registered account, enter
   **Country: US**, **Dial code: 1**, and its account/password **once**.
   Do not send the password to chat, include it in screenshots or commit it.
5. Click **Save ANRAN account to Linux keyring**. Wait for the exact fixed
   confirmation **ANRAN credentials saved and verified in Linux keyring.
   No login was sent.** The app verifies the save by reading it back.
6. Close Ocularium and launch it as usual with `cargo run --release`.
   Reopen the ANRAN panel and select **ANRAN app**. The form should
   restore the masked account/password fields and show **Country: US**,
   **Dial code: 1**, and **ANRAN account restored from Linux keyring.
   No login was sent.**
7. Stop QA. A screenshot of the fixed confirmation/status and masked fields
   is sufficient. Do not click the cloud connection button or run extra tests.

## Strict stop rule

The first build error, missing `secret-tool`, keyring unlock problem,
unexpected window behavior or incorrect status **ends this QA attempt**.
Do not install packages, retry a login, re-enter credentials, or diagnose
the environment on the user's side. Report the first error exactly as shown.

## Security / recovery

- The saved secret is in the Linux Secret Service collection, with the
  static selectors `application=ocularium` and `entry=anran-v1`;
  Ocularium never writes it into its own JSON registry.
- **Forget saved ANRAN account** deletes this keyring entry.
- **Clear form and result (keep keyring)** intentionally leaves the keyring
  entry intact.
- Login always needs a separate explicit app/pairing confirmation, user
  consent acknowledging potential phone-app eviction, and an explicit click.
- The real vendor camera-list test is **separate** and requires renewed
  consent after this local keyring check works.
