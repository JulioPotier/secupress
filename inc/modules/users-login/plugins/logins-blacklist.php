<?php
/*
Module Name: Logins Blacklist
Description: Forbid some usernames to be used.
Main Module: users_login
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );


/*
 * As soon as we are sure a user is connected, and before any redirection, check if the user login is not blacklisted.
 * If he is, he can't access the administration area and is asked to change it.
 *
 * @since 1.0
 */
add_action( 'auth_redirect', 'secupress_auth_redirect_blacklist_logins' );

function secupress_auth_redirect_blacklist_logins( $user_id ) {

	$user = get_userdata( $user_id );
	$list = secupress_get_module_option( 'bad-logins_blacklist-logins-list', secupress_blacklist_logins_list_default_string(), 'users-login' );

	if ( strpos( "\n$list\n", "\n$user->user_login\n" ) === false ) {
		// Good, the login is not blacklisted.
		return;
	}

	$nonce_action = 'secupress-backlist-logins-new-login-' . $user_id;
	$error        = '';

	// A new login is submitted.
	if ( isset( $_POST['secupress-backlist-logins-new-login'] ) ) {

		if ( empty( $_POST['_wpnonce'] ) || ! wp_verify_nonce( $_POST['_wpnonce'], $nonce_action ) ) {
			wp_die( __( 'Cheatin&#8217; uh?' ) );
		}

		if ( empty( $_POST['secupress-backlist-logins-new-login'] ) ) {
			// Empty username.
			$error = __( 'Username required', 'secupress' );
		} else {
			// Sanitize the submitted username.
			$user_login = sanitize_user( $_POST['secupress-backlist-logins-new-login'], true );

			if ( strpos( "\n$list\n", "\n$user_login\n" ) !== false ) {
				// The new login is blacklisted.
				$error = __( 'This username is also blacklisted', 'secupress' );
			} else {
				// Good, change the user login.
				$inserted = secupress_blacklist_logins_change_user_login( $user_id, $user_login );

				if ( is_wp_error( $inserted ) ) {
					// Too bad, try again.
					$error = $inserted->get_error_message();
				} else {
					// Send the new login by email.
					secupress_blacklist_logins_new_user_notification( $user_id );

					// Kill the user session.
					wp_clear_auth_cookie();
					wp_destroy_current_session();

					// Redirect the user to the login page.
					$login_url = wp_login_url( secupress_get_current_url( 'raw' ), true );
					$login_url = add_query_arg( 'secupress-relog', 1, $login_url );
					wp_redirect( $login_url );
					exit();
				}
			}
		}
	}

	// Allowed characters for the login.
	$allowed = esc_attr( secupress_blacklist_logins_allowed_characters() );

	// The form.
	?><!DOCTYPE html>
<html <?php language_attributes(); ?>>
	<head>
		<meta charset="<?php echo esc_attr( strtolower( get_bloginfo( 'charset' ) ) ); ?>" />
		<title><?php _e( 'Please change your username', 'secupress' ); ?></title>
		<meta content="initial-scale=1.0" name="viewport" />
		<style>
html, body {
	width: 100%;
	margin: 0;
	font: 1em/1.5 Arial, Helvetica, sans-serif;
	color: #313131;
	background: #F1F1F1;
}
form,
div {
	max-width: 400px;
	padding: 20px 10px;
	margin: 10px auto;
}
div {
	text-align: center;
}
h1 {
	margin: 0 0 1em;
	font-size: 2em;
	line-height: 1.1;
}
p {
	margin: 0 0 1.5em;
}
a {
	color: #205081;
}
a:active,
a:hover,
a:focus {
	color: #2d75bd;
}
.error {
	padding: .5em 1em;
	border: solid 2px #ff8383;
	background: #ffb1b1;
	border-radius: .2em;
}
label {
	display: inline-block;
	margin-bottom: .5em;
}
[type="text"] {
	box-sizing: border-box;
	width: 100%;
	padding: .5em;
	border: 1px solid rgba(83,69,55,.3);
	margin: 0 0 1.5em;
	border-radius: 3px;
	font-size: 1em;
	font-family: inherit;
	color: inherit;
}
[type="text"]:focus {
	border-color: rgb(156,144,138);
}
[type="submit"] {
	position: relative;
	display: inline-block;
	line-height: 1.2;
	padding: .65em 1.8em;
	border: none;
	margin: 0 0 .5em 0;
	background: #205081;
	-webkit-appearance: none;
	   -moz-appearance: none;
	        appearance: none;
	box-shadow: none;
	border-radius: .214em;
	color: #fff;
	font-size: .875em;
	font-family: inherit;
	text-align: center;
	text-transform: uppercase;
	text-decoration: none;
	vertical-align: middle;
	cursor: pointer;
	-webkit-transition: all .3s ease;
	        transition: all .3s ease;
}
[type="submit"]:focus,
[type="submit"]:hover {
	background-color: #2d75bd;
}
		</style>
	</head>
	<body>
		<form method="post">
			<h1><?php _e( 'Please change your username', 'secupress' ); ?></h1>
			<p><?php
			printf(
				/* translators: 1 is a user name, 2 is a link "to the site" */
				__( 'Your current username, %1$s, is blacklisted. You will not be able to reach the administration area until you change your username. Meanwhile, you still have access %2$s.', 'secupress' ),
				'<strong>' . esc_html( $user->user_login ) . '</strong>',
				'<a href="' . esc_url( user_trailingslashit( home_url() ) ) . '">' . __( 'to the site', 'secupress' ) . '</a>'
			);
			?></p>
			<?php
			if ( $error ) {
				echo '<p class="error">' . $error . '</p>';
			}
			?>
			<label for="new-login"><?php _e( 'New username:', 'secupress' ); ?></label><br/>
			<input type="text" id="new-login" name="secupress-backlist-logins-new-login" value="" maxlength="60" required="required" aria-required="true" pattern="[A-Za-z0-9 _.\-@]{2,60}" autocorrect="off" autocapitalize="off" title="<?php echo $allowed; ?>"/><br/>
			<input type="submit" />
			<?php wp_nonce_field( $nonce_action ) ?>
		</form>
	</body>
</html><?php
	die();
}


/*
 * Change a user login.
 *
 * @since 1.0
 *
 * @param (int)    $user_id    I let you guess what it is.
 * @param (string) $user_login Well...
 *
 * @return (int|object) User ID or WP_Error object on failure.
 */
function secupress_blacklist_logins_change_user_login( $user_id, $user_login ) {
	global $wpdb;

	// user_login must be between 1 and 60 characters.
	if ( empty( $user_login ) ) {
		return new WP_Error( 'empty_user_login', __( 'Cannot create a user with an empty login name.' ) );
	} elseif ( mb_strlen( $user_login ) > 60 ) {
		return new WP_Error( 'user_login_too_long', __( 'Username may not be longer than 60 characters.' ) );
	}

	if ( username_exists( $user_login ) ) {
		return new WP_Error( 'existing_user_login', __( 'Sorry, that username already exists!' ) );
	}

	$wpdb->update( $wpdb->users, array( 'user_login' => $user_login ), array( 'ID' => $user_id ) );

	wp_cache_delete( $user_id, 'users' );
	wp_cache_delete( $user_login, 'userlogins' );

	return $user_id;
}


/*
 * Send an email notification to a user with his/her login.
 *
 * @since 1.0
 *
 * @param (int|object) $user A user ID or a user object.
 */
function secupress_blacklist_logins_new_user_notification( $user ) {
	$user = is_object( $user ) ? $user : get_userdata( $user );

	// The blogname option is escaped with esc_html on the way into the database in sanitize_option
	// we want to reverse this for the plain text arena of emails.
	$blogname = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );

	$message  = sprintf( __( 'Username: %s' ), $user->user_login ) . "\r\n\r\n"; // WP i18n
	$message .= wp_login_url() . "\r\n";

	wp_mail( $user->user_email, sprintf( __( '[%s] Your username info', 'secupress' ), $blogname ), $message );
}


/*
 * Display a message on the login form after the new login creation.
 *
 * @since 1.0
 *
 * @param (object) $errors      WP Error object.
 * @param (string) $redirect_to Redirect destination URL.
 *
 * @return (object) WP Error object.
 */
add_filter( 'wp_login_errors', 'secupress_blacklist_logins_display_login_message', 10, 2 );

function secupress_blacklist_logins_display_login_message( $errors, $redirect_to ) {
	if ( empty( $_GET['secupress-relog'] ) ) {
		return $errors;
	}

	if ( empty( $errors ) ) {
		$errors = new WP_Error();
	}

	$errors->add( 'secupress_relog', __( 'You will receive your new login in your mailbox.', 'secupress' ), 'message' );

	return $errors;
}


/*
 * In `wp_insert_user()`, add our forbidden logins.
 *
 * @since 1.0
 * @since WP 4.4.0
 *
 * @param (object) $errors      WP Error object.
 * @param (string) $redirect_to Redirect destination URL.
 *
 * @return (object) WP Error object.
 */
add_filter( 'illegal_user_logins', 'secupress_blacklist_logins_add_illegal_user_logins' );

function secupress_blacklist_logins_add_illegal_user_logins( $user_logins ) {
	// `secupress_blacklist_logins_list_default()` does not exists on frontend.
	if ( function_exists( 'secupress_blacklist_logins_list_default' ) ) {
		return array_merge( $user_logins, secupress_blacklist_logins_list_default() );
	}
	return $user_logins;
}
