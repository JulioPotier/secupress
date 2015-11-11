<?php
/*
Module Name: Additionnal Password Double Authentication
Description: When you try to log in, you'll have to enter another password, without it, you can't log in.
Main Module: users_login
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

add_action( 'login_form_website_password', 'secupress_password_login_form_add_form' );
function secupress_password_login_form_add_form() {
	global $wpdb;
	$message = array();
	$errors = null;
	$messages[] = __( 'Your account or role requires an additionnal verification step.', 'secupress' );
	$do_delete = $show_form = true;

	$CLEAN = array();
	$CLEAN['token'] = isset( $_REQUEST['token'] ) ? sanitize_key( $_REQUEST['token'] ) : false;
	$CLEAN['rememberme'] = isset( $_REQUEST['rememberme'] );
	$CLEAN['uid'] = $wpdb->get_col( $wpdb->prepare( "SELECT user_id FROM $wpdb->usermeta WHERE meta_value = %s", $CLEAN['token'] ) );

	if ( ! $CLEAN['token'] || 1 != count( $CLEAN['uid'] ) ) {
		secupress_die( sprintf( __( 'Invalid Link.<br>Please try to <a href="%s">log in again</a>.', 'secupress' ), wp_login_url( '', true ) ) );
	} elseif ( isset( $_POST['website_password'], $_POST['token'] ) ) {
		$CLEAN['uid'] = (int) reset( $CLEAN['uid'] );
		$time = get_user_meta( $CLEAN['uid'], 'auth_timeout', true );
		$new_password = secupress_get_module_option( 'double_auth_password', false, 'users_login' );
		if ( $time >= time() ) {
			if ( wp_check_password( $_POST['website_password'], $new_password, $user_by_check->ID ) ) {
				$secure_cookie = apply_filters( 'secure_signon_cookie', is_ssl(), array( 'user_login' => $user_by_check->user_login, 'user_password' => time() ) ); // we don't have the real password, just pass something
				wp_set_auth_cookie( $CLEAN['uid'], $CLEAN['rememberme'], $secure_cookie );
				$user = get_user_by( 'id', $CLEAN['uid'] );
				do_action( 'wp_login', $user->user_login, $user );
				$redirect_to = apply_filters( 'login_redirect', admin_url(), admin_url(), $user_by_check );
				do_action( 'emaillink_autologin_success', $user );
				wp_redirect( $redirect_to );
				die( 'login_redirect' );
			} else {
				do_action( 'secupress_autologin_error', $CLEAN['uid'], $CLEAN['token'], 'invalid password' );
				add_action( 'login_head', 'wp_shake_js', 12 );
				$errors = new WP_Error( 'invalid_password', __( '<strong>ERROR</strong>: Invalid Website Password.', 'secupress' ) );
				$do_delete = false;
			}
		} else {
			do_action( 'secupress_autologin_error', $CLEAN['uid'], $CLEAN['token'], 'expired key' );
			$errors = new WP_Error( 'expired_key', sprintf( __( 'You waited too long between the first step and now.<br>Please try to <a href="%s">log in again</a>.', 'secupress' ) . '</p>', wp_login_url( '', true ) ) );
			$show_form = false;
		}
		if ( $do_delete ) {
			delete_user_meta( $CLEAN['uid'], 'password_token' );
			delete_user_meta( $CLEAN['uid'], 'auth_timeout' );
		}
	}
	$messages = count( $messages ) ? '<p class="message error">' . implode( '</p><br><p class="message">', $messages ) . '</p><br>' : '';
	login_header( __( 'Log In' ), $messages, $errors );
	if ( $show_form ) {
		?>
		<form name="loginform" id="loginform" action="<?php echo esc_url( site_url( 'wp-login.php?action=website_password&token=' . esc_attr( $CLEAN['token'] ) ) ); ?>" method="post">
			<p>
				<label for="website_password"><?php echo apply_filters( 'secupress_double_auth_title', __( 'Website Password', 'secupress' ) ); ?><br />
				<input type="text" name="website_password" id="website_password" required="required" class="input" value="" size="20" /></label>
			</p>
			<input type="hidden" name="token" value="<?php echo esc_attr( $CLEAN['token'] ); ?>">
			<?php if ( $CLEAN['rememberme'] ) { ?>
			<input type="hidden" name="rememberme" value="forever">
			<?php } ?>
			<p class="submit">
				<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="<?php esc_attr_e('Log In'); ?>" />
			</p>
		</form>
		<?php
		login_footer( 'website_password' );
	} else {
		login_footer();
	}
	die();
}

add_action( 'login_form', 'secupress_password_login_form_add_field' );
function secupress_password_login_form_add_field() {
	if ( -1 == secupress_get_module_option( 'double_auth_affected_role', false, 'users_login' ) ) {
	?>
	<p>
		<label><?php _e( 'Website\'s Password', 'secupress' ); ?><br />
		<input name="website_password" type="password" class="input" id="website_password" /></label>
	</p>
	<?php
	}
}

add_filter( 'authenticate', 'secupress_password_login', PHP_INT_MAX, 2 );
function secupress_password_login( $raw_user, $username ) {
    if ( ! is_wp_error( $raw_user ) && ! empty( $_POST ) ) {
		if ( secupress_is_affected_role( 'users_login', 'double_auth', $raw_user ) ) {
			// Generate something random for a token.
			$token = wp_hash( wp_generate_password( 32, false ), 'nonce' );

			update_user_meta( $raw_user->ID, 'password_token', $token );
			update_user_meta( $raw_user->ID, 'auth_timeout', time() + 10 * MINUTE_IN_SECONDS );
			$raw_user = null;
			$rememberme = isset( $_POST['rememberme'] );
			$redirect_to = add_query_arg( array('action' => 'website_password',
												'token' => $token,
												'rememberme' => $rememberme ),
											wp_login_url()
										);
			wp_redirect( $redirect_to );
			die();
		} elseif( -1 === secupress_is_affected_role( 'users_login', 'double_auth', $raw_user ) ) {

		    $new_password = secupress_get_module_option( 'double_auth_password', false, 'users_login' );

		    if ( ! isset( $_POST['website_password'] ) || $_POST['website_password'] !== $new_password ) {

		        add_action( 'login_head', 'wp_shake_js', 12 );

		        return new WP_Error( 'authentication_failed', __( '<strong>ERROR</strong>: Invalid Website Password.', 'secupress' ) );
		    }
		    do_action( 'emaillink_autologin_success', $raw_user );

		}
	}
    return $raw_user;
}

add_action( 'login_footer', 'secupress_password_add_js' );
function secupress_password_add_js() {
	if ( ! isset( $_GET['action'] ) || 'website_password' != $_GET['action'] ) {
		return;
	}
?>
<script>
var $input = document.getElementById('website_password');
$input.onfocus = function() { $input.setAttribute('type','text'); }
$input.onblur = function() { $input.setAttribute('type','password'); }
document.getElementById('website_password').focus();
</script>
<?php
}

add_action( 'retrieve_password_key', 'secupress_password_retrieve' );
function secupress_password_retrieve( $user ) {
	$user = get_user_by( 'login', $user );
	if ( is_a( $user, 'WP_User' ) && user_can( $user, 'administrator' ) ) {
		$key = wp_generate_password( 10, false );
		$message = sprintf( '<p>' . __( 'You just requested a new account password, maybe you also want to <b>reset the website\'s password</b> set by %1$s.', 'secupress' ), SECUPRESS_PLUGIN_NAME ) . '</p>' . "\r\n";
		$message .= sprintf( '<p>' . __( 'Yes, <a href="%1$s">reset the website\'s password</a>, thanks.', 'secupress' ), admin_url( 'admin-post.php?action=reset_website_password&_wpnonce=' . $key ) ) . '</p>' . "\r\n";
		$message .= '<p><i>' . __( 'Note: All administrators will be mailed with the new password.', 'secupress' ) . '</i></p>' . "\r\n";
		set_transient( 'secupress_reset_website_password', $key, 10 * MINUTE_IN_SECONDS );
		// Email the user
		wp_mail( $user->user_email, sprintf( __( '[%s] Reset Website\'s Password', 'secupress' ), get_bloginfo( 'name' ) ), $message, 'content-type: text/html' );
	}
}

add_action( 'admin_post_nopriv_reset_website_password', 'secupress_reset_website_password' );
add_action( 'admin_post_reset_website_password', 'secupress_reset_website_password' );
function secupress_reset_website_password() {
	if ( isset( $_GET['_wpnonce'] ) && $_GET['_wpnonce'] === get_transient( 'secupress_reset_website_password' ) ) {
		delete_transient( 'secupress_reset_website_password' );
		$new_password = wp_generate_password();
		secupress_update_module_option( 'double_auth_password', $new_password, 'users_login' );
		$message = sprintf( '<p>' . __( 'A new website\'s password has been generated, you can now use <b>%1$s</b>, please change it.', 'secupress' ), $new_password ) . '</p>' . "\r\n";
		$message .= '<p><i>' . __( 'Note: All administrators have been mailed with the new password.', 'secupress' ) . '</i></p>' . "\r\n";
		// Email the users
		$admins = get_users( array( 'role' => 'administrator' ) );
		foreach ( $admins as $admin ) {
			wp_mail( $admin->user_email, sprintf( __( '[%s] Reset Website\'s Password', 'secupress' ), get_bloginfo( 'name' ) ), $message, 'content-type: text/html' );
		}
		secupress_die( __( 'Website\'s Password Changed, check your e-mail for the confirmation.', 'secupress' ) );
	}
}