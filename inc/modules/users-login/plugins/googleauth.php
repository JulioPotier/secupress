<?php
/*
Module Name: Mobile Authenticator
Description: Two-Factor Authentication using a mobile app as OTP (One Time Password) generator.
Main Module: users-login
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

if ( ! function_exists( '__secupress_base32_verify' ) ) :
/**
 * Check the verification code entered by the user.
 */
function __secupress_base32_verify( $secretkey, $thistry, $lasttimeslot ) {

    require_once( dirname( __FILE__ ) . '/inc/php/base32.php' );


	$tm = floor( time() / 30 );
	
	$secretkey = Base32::decode( $secretkey );
	// Key from 30 seconds before is also valid.
	for ($i=-1; $i<=0; $i++) {
		// Pack time into binary string
		$time=chr(0).chr(0).chr(0).chr(0).pack('N*',$tm+$i);
		// Hash it with users secret key
		$hm = hash_hmac( 'SHA1', $time, $secretkey, true );
		// Use last nipple of result as index/offset
		$offset = ord(substr($hm,-1)) & 0x0F;
		// grab 4 bytes of the result
		$hashpart=substr($hm,$offset,4);
		// Unpak binary value
		$value=unpack("N",$hashpart);
		$value=$value[1];
		// Only 32 bits
		$value = $value & 0x7FFFFFFF;
		$value = $value % 1000000;
		if ( $value === (int) $thistry ) {
			// Check for replay (Man-in-the-middle) attack.
			if ( $lasttimeslot >= ($tm+$i) ) {
				do_action( 'secupress.doubleauth.mitm', $secretkey );
				return false;
			}
			// Return timeslot in which login happened.
			return $tm+$i;
		}
	}
	return false;
}

endif;

/**
 * Get doubleauth a user option easily
 **/
function secupress_doubleauth_get_user_option( $option, $uid = 0 ) {
	$current_user = wp_get_current_user();
	$user_id = $uid ? $uid : $current_user->ID;
	return get_user_option( 'secupress_doubleauth_' . $option, $user_id );
}

function secupress_doubleauth_delete_user_option( $option, $uid = 0 ) {
	$current_user = wp_get_current_user();
	$user_id = $uid ? $uid : $current_user->ID;
	return delete_user_option( $user_id, 'secupress_doubleauth_' . $option );
}

function secupress_doubleauth_update_user_option( $option, $value, $uid = 0 ) {
	$current_user = wp_get_current_user();
	$user_id = $uid ? $uid : $current_user->ID;
	return update_user_option( $user_id, 'secupress_doubleauth_' . $option, $value );
}

add_action( 'login_head', 'secupress_doubleauth_css' );
function secupress_doubleauth_css() {
?>
<style>
	.doubleauth{font-size: 2em; text-align: center; font-weight: bold; letter-spacing: 0.2em; border-radius: 8px; color: #666;}
	.button-full{width: 100%}
	.dashright{float:right}
	.authinfo { padding:5px 0px;display:inline-block}
	.authinfo img{height:72px; width:72px; float:left; padding-right: 7px }
	.no-button,.no-button:hover, .no-button:focus {cursor: pointer;text-decoration: none; padding: 0; border: none; margin: 0; font-size: 1em; line-height: inherit; font-style:inherit; text-align: left; text-transform: inherit; color: #427FED; text-shadow: none; background: none; -webkit-border-radius: 0; border-radius: 0; -webkit-box-shadow: none; box-shadow: none; }
	#form_alt{padding:26px 24px 26px}
</style>
<?php
}

function secupress_print_doubleauth_head_css() {
?>
<style>
.login h1 a{background-image: url('http://<?php echo $server; ?>.gravatar.com/avatar/<?php echo md5( $user->user_email ); ?>?s=180&d=<?php echo admin_url( '/images/wordpress-logo.svg?ver=20131107' ); ?>') !important; border-radius: 100%}
.error{color:red}
</style>
<?php
}

add_action( 'login_form_doubleauth_lost_redir', '__secupress_doubleauth_lost_form_redir' );
function __secupress_doubleauth_lost_form_redir() {
	global $wpdb;

	if ( ! isset( $_POST['doubleauth_lost_method'] ) ) {
		secupress_die( sprintf( __( 'Invalid Link.<br>Please try to <a href="%s">log in again</a>.', 'secupress' ), wp_login_url( '', true ) ) );
	}

	$CLEAN               = array();
	$CLEAN['token']      = isset( $_REQUEST['token'] ) ? sanitize_key( $_REQUEST['token'] ) : false;
	$CLEAN['rememberme'] = isset( $_REQUEST['rememberme'] );
	$CLEAN['uid']        = $wpdb->get_col( $wpdb->prepare( "SELECT user_id FROM $wpdb->usermeta WHERE meta_value = %s", $CLEAN['token'] ) );
	$CLEAN['uid']        = (int) reset( $CLEAN['uid'] );
	$user                = get_user_by( 'id', $CLEAN['uid'] );

	if ( user_can( $user, 'exist' ) ) {

		$time = secupress_doubleauth_get_user_option( 'timeout', $CLEAN['uid'] );

		if ( $time >= time() ) {

			secupress_doubleauth_update_user_option( 'lost', '1', $user->ID );
			secupress_doubleauth_update_user_option( 'timeout', time() + 10 * MINUTE_IN_SECONDS, $user->ID );

			$redirect_to = add_query_arg( array( 'action' => 'doubleauth_lost_form_' . sanitize_key( $_POST['doubleauth_lost_method'] ),
												 'token' => $CLEAN['token'],
												 'rememberme' => $CLEAN['rememberme'] ),
											wp_login_url()
										);
			wp_redirect( $redirect_to );
			die();

		} else {

			do_action( 'secupress.doubleauth.autologin.error', $user, 'expired key' );
			secupress_die( sprintf( __( 'You waited too long between the first step and now.<br>Please try to <a href="%s">log in again</a>.', 'secupress' ) . '</p>', wp_login_url( '', true ) ) );

		}

	} else {

		if ( ! $CLEAN['token'] || 1 != count( $CLEAN['uid'] ) ) {
			secupress_die( sprintf( __( 'Invalid Link.<br>Please try to <a href="%s">log in again</a>.', 'secupress' ), wp_login_url( '', true ) ) );
		}

	}
}

add_action( 'login_form_doubleauth_lost_form_backupcode', '__secupress_doubleauth_lost_form_backupcode' );
function __secupress_doubleauth_lost_form_backupcode() {
	global $wpdb;

	$messages  = array();
	$errors    = null;
	$do_delete = true;
	$show_form = true;
	
	if ( isset( $_GET['emailed'] ) ) {
		$messages[] = __( 'You will receive an e-mail on your backup e-mail address, containing a backup code.', 'secupress' );
	}

	$CLEAN               = array();
	$CLEAN['token']      = isset( $_REQUEST['token'] ) ? sanitize_key( $_REQUEST['token'] ) : false;
	$CLEAN['rememberme'] = isset( $_REQUEST['rememberme'] );
	$CLEAN['uid']        = $wpdb->get_col( $wpdb->prepare( "SELECT user_id FROM $wpdb->usermeta WHERE meta_value = %s", $CLEAN['token'] ) );
	$CLEAN['uid']        = (int) reset( $CLEAN['uid'] );
	$user                = get_user_by( 'id', $CLEAN['uid'] );
	$server              = rand( 0, 3 );

	if ( ! $CLEAN['token'] || 1 != count( $CLEAN['uid'] ) || ! secupress_doubleauth_get_user_option( 'lost', $CLEAN['uid'] ) ) {

		secupress_die( sprintf( __( 'Invalid Link.<br>Please try to <a href="%s">log in again</a>.', 'secupress' ), wp_login_url( '', true ) ) );

	} elseif ( isset( $_POST['otp'], $_POST['token'] ) ) {

		$time = secupress_doubleauth_get_user_option( 'timeout', $CLEAN['uid'] );

		if ( $time >= time() ) {

			$backupcodes = secupress_doubleauth_get_user_option( 'backupcodes', $CLEAN['uid'] );

			if ( $timeslot = in_array( $_POST['otp'], $backupcodes ) ) {

				secupress_doubleauth_delete_user_option( 'lost', $user->ID );
				$backupcodes[ array_search( $_POST['otp'], $backupcodes ) ] = false;
				secupress_doubleauth_update_user_option( 'backupcodes', $backupcodes, $user->ID );
				$secure_cookie = apply_filters( 'secure_signon_cookie', is_ssl(), array( 'user_login' => $user_by_check->user_login, 'user_password' => time() ) ); // we don't have the real password, just pass something
				wp_set_auth_cookie( $CLEAN['uid'], $CLEAN['rememberme'], $secure_cookie );
				do_action( 'wp_login', $user->user_login, $user );
				$redirect_to = apply_filters( 'login_redirect', admin_url(), admin_url(), $user_by_check );
				do_action( 'secupress.doubleauth.autologin.success', $user );
				wp_redirect( $redirect_to );
				die( 'login_regirect ' . __LINE__ );

			} else {

				do_action( 'secupress.doubleauth.autologin.error', $user, 'invalid password' );
				add_action( 'login_head', 'wp_shake_js', 12 );
				$errors = new WP_Error( 'invalid_password', __( '<strong>ERROR</strong>: Invalid Double Authentication Backup Code.', 'secupress' ) );
				$do_delete = false;

			}

		} else {

			do_action( 'secupress.doubleauth.autologin.error', $user, 'expired key' );
			$errors    = new WP_Error( 'expired_key', sprintf( __( 'You waited too long between the first step and now.<br>Please try to <a href="%s">log in again</a>.', 'secupress' ) . '</p>', wp_login_url( '', true ) ) );
			$show_form = false;

		}

		if ( $do_delete ) {
			secupress_doubleauth_delete_user_option( 'token', $CLEAN['uid'] );
			secupress_doubleauth_delete_user_option( 'timeout', $CLEAN['uid'] );
		}
	}

	$messages = count( $messages ) ? '<p class="message error">' . implode( '</p><br><p class="message">', $messages ) . '</p><br>' : '';

	login_header( __( 'Log In' ), $messages, $errors );

	if ( $show_form ) {
		secupress_print_doubleauth_head_css();
		?>
		<form name="loginform" id="loginform" action="<?php echo esc_url( site_url( 'wp-login.php?action=doubleauth_lost_form_backupcode' ) ); ?>" method="post">
			<p>
			    <label>
			    <h3><?php printf( __( '2-Step Verification for %s', 'secupress' ), get_bloginfo( 'name', 'display' ) ); ?></h3>
			    <span class="authinfo">
			    	<img src="<?php echo plugins_url( '/inc/img/backup-codes-icon_2X.png', __FILE__ ) ?>">
			    	<i><?php _e( 'Enter one of your backup codes.', 'secupress' ); ?></i>
			    </span>
			    <input type="text" class="doubleauth" onkeypress="return event.charCode >= 48 && event.charCode <= 57 || event.charCode == 13" name="otp" id="otp" size="20" style="ime-mode: inactive;" /></label>
			</p>
			<input type="hidden" name="token" value="<?php echo esc_attr( $CLEAN['token'] ); ?>">
			<?php if ( $CLEAN['rememberme'] ) { ?>
			<input type="hidden" name="rememberme" value="forever">
			<?php } ?>
			<p class="submit">
				<input type="submit" name="wp-submit" id="main-submit" class="button button-primary button-large button-full" value="<?php esc_attr_e('Verify'); ?>" />
			</p>
		</form>
		<?php
		login_footer( 'otp' );
	} else {
		login_footer();
	}
	die();
}

add_action( 'login_form_doubleauth_lost_form_backupmail', '__secupress_doubleauth_lost_form_backupmail' );
function __secupress_doubleauth_lost_form_backupmail() {
	global $wpdb;

	$CLEAN = array();
	$CLEAN['token']      = isset( $_REQUEST['token'] ) ? sanitize_key( $_REQUEST['token'] ) : false;
	$CLEAN['rememberme'] = isset( $_REQUEST['rememberme'] );
	$CLEAN['uid']        = $wpdb->get_col( $wpdb->prepare( "SELECT user_id FROM $wpdb->usermeta WHERE meta_value = %s", $CLEAN['token'] ) );
	$CLEAN['uid']        = (int) reset( $CLEAN['uid'] );
	$user                = get_user_by( 'id', $CLEAN['uid'] );

	if ( user_can( $user, 'exist' ) && is_email( get_user_option( 'backup_email', $user->ID ) ) ) {

		$codes = secupress_doubleauth_get_user_option( 'backupcodes', $user->ID );

		if ( is_array( $codes ) && count( array_filter( $codes ) ) ) {

 			$code = reset( array_filter( $codes ) );

		} else {

			$code = str_pad( wp_rand( 0, 9999999999 ), 10, '0', STR_PAD_BOTH );
			$codes[1] = $code;
			secupress_doubleauth_update_user_option( 'backupcodes', $codes, $user->ID );

		}

		secupress_doubleauth_delete_user_option( 'timeout', $user->ID );
		secupress_doubleauth_delete_user_option( 'lost', $user->ID );

		$subject = apply_filters( 'secupress.doubleauth.backupcode_email.subject', 
			sprintf( __( '[%1$s] Mobile Authenticator Backup Code request', 'secupress' ), get_bloginfo( 'name' ) ) );
		$message = apply_filters( 'secupress.doubleauth.backupcode_email.message', 
			sprintf( __( 'Hello %1$s, you asked for a backup code, here it comes: %2$s.' ), $user->display_name, $code ) );
			wp_mail( get_user_option( 'backup_email', $user->ID ), $subject, $message, 'content-type: text/html' );
			wp_redirect( add_query_arg( array( 'action' => 'doubleauth_lost_form_backupcode', 'token' => $CLEAN['token'], 'rememberme' => $CLEAN['rememberme'], 'emailed' => 1 ), wp_login_url() ) );
			die();
	}
}

add_action( 'login_form_doubleauth', '__secupress_doubleauth_login_form_add_form' );
function __secupress_doubleauth_login_form_add_form() {
	global $wpdb;

	$messages   = array();
	$errors     = null;
	$messages[] = __( 'Your account requires an additionnal verification step.', 'secupress' );
	$do_delete  = $show_form = true;

	$CLEAN               = array();
	$CLEAN['token']      = isset( $_REQUEST['token'] ) ? sanitize_key( $_REQUEST['token'] ) : false;
	$CLEAN['rememberme'] = isset( $_REQUEST['rememberme'] );
	$CLEAN['uid']        = $wpdb->get_col( $wpdb->prepare( "SELECT user_id FROM $wpdb->usermeta WHERE meta_value = %s", $CLEAN['token'] ) );
	$CLEAN['uid']        = (int) reset( $CLEAN['uid'] );
	$user                = get_user_by( 'id', $CLEAN['uid'] );
	$server              = rand( 0, 3 );

	if ( ! $CLEAN['token'] || 1 != count( $CLEAN['uid'] ) ) {

		secupress_die( sprintf( __( 'Invalid Link.<br>Please try to <a href="%s">log in again</a>.', 'secupress' ), wp_login_url( '', true ) ) );

	} elseif ( isset( $_POST['otp'], $_POST['token'] ) ) {

		$time = secupress_doubleauth_get_user_option( 'timeout', $CLEAN['uid'] );

		if ( $time >= time() ) {

			$doubleauth_secret = secupress_doubleauth_get_user_option( 'secret', $CLEAN['uid'] );
			$lasttimeslot      = secupress_doubleauth_get_user_option( 'lasttimeslot', $CLEAN['uid'] );

			if ( $timeslot = __secupress_base32_verify( $doubleauth_secret, $_POST['otp'], $lasttimeslot ) ) {

				secupress_doubleauth_update_user_option( 'lasttimeslot', $timeslot, $user->ID );
				$secure_cookie = apply_filters( 'secure_signon_cookie', is_ssl(), array( 'user_login' => $user->user_login, 'user_password' => time() ) ); // we don't have the real password, just pass something
				wp_set_auth_cookie( $CLEAN['uid'], $CLEAN['rememberme'], $secure_cookie );
				do_action( 'wp_login', $user->user_login, $user );
				$redirect_to = apply_filters( 'login_redirect', admin_url(), admin_url(), $user );
				do_action( 'secupress.doubleauth.autologin.success', $user );
				wp_redirect( $redirect_to );
				die( 'login_redirect ' . __LINE__ );

			} else {

				do_action( 'secupress.doubleauth.autologin.error', $user, 'invalid password' );
				add_action( 'login_head', 'wp_shake_js', 12 );
				$errors = new WP_Error( 'invalid_password', __( '<strong>ERROR</strong>: Wrong Authentication Code. Try again.', 'secupress' ) );
				$do_delete = false;

			}

		} else {

			do_action( 'secupress.doubleauth.autologin.error', $user, 'expired key' );
			$errors = new WP_Error( 'expired_key', sprintf( __( 'You waited too long between the first step and now.<br>Please try to <a href="%s">log in again</a>.', 'secupress' ) . '</p>', wp_login_url( '', true ) ) );
			$show_form = false;

		}

		if ( $do_delete ) {
			secupress_doubleauth_delete_user_option( 'token', $CLEAN['uid'] );
			secupress_doubleauth_delete_user_option( 'timeout', $CLEAN['uid'] );
		}
	}

	$messages = count( $messages ) ? '<p class="message error">' . implode( '</p><br><p class="message">', $messages ) . '</p><br>' : '';

	login_header( __( 'Log In' ), $messages, $errors );

	if ( $show_form ) {

		$attempts = isset( $_POST['attempts'] ) ? (int) $_POST['attempts'] : 0;
		++$attempts;

		secupress_print_doubleauth_head_css();
		?>
		<form name="loginform" id="loginform" action="<?php echo esc_url( site_url( 'wp-login.php?action=doubleauth' ) ); ?>" method="post">
			<p>
				<label>
				<h3><?php printf( __( '2-Step Verification for %s', 'secupress' ), get_bloginfo( 'name', 'display' ) ); ?></h3>
				<span class="authinfo">
					<img src="<?php echo plugins_url( '/inc/img/authenticator-Android-phone-icon_2X.png', __FILE__ ); ?>">
					<i><?php _e( 'Enter the verification code generated by your mobile application.', 'secupress' ); ?></i>
				</span>
				<input type="text" placeholder="******" class="doubleauth" onkeypress="return event.charCode >= 48 && event.charCode <= 57 || event.charCode == 13" name="otp" id="otp" maxlength="6" size="20" style="ime-mode: inactive;" /></label>
			</p>
			<input type="hidden" name="token" value="<?php echo esc_attr( $CLEAN['token'] ); ?>">
			<?php if ( $CLEAN['rememberme'] ) { ?>
			<input type="hidden" name="rememberme" value="forever">
			<?php } ?>
			<input type="hidden" name="attempts" value="<?php echo $attempts; ?>">
			<p class="submit">
				<input type="submit" name="wp-submit" id="main-submit" class="button button-primary button-large button-full" value="<?php esc_attr_e('Verify'); ?>" />
			</p>
			<?php if ( $attempts > 2 ) { ?>
				<p class="error"><?php _e( 'It looks like you entered a wrong code again.<br>Click on "Problems with your code" below and try to use a backup code to log in.', 'secupress' ); ?></p>
			<?php } ?>
		</form>

		<form action="<?php echo esc_url( site_url( 'wp-login.php?action=doubleauth_lost_redir' ) ); ?>" method="post" id="form_alt">
			<input type="hidden" name="token" value="<?php echo esc_attr( $CLEAN['token'] ); ?>">
			<?php if ( $CLEAN['rememberme'] ) { ?>
				<input type="hidden" name="rememberme" value="forever">
			<?php } ?>
			<button type="button" class="no-button button-full hide-if-no-js" id="help_lost"><?php _e( 'Problems with your code?', 'secupress' ); ?> <span class="dashicons dashicons-arrow-right-alt2 dashright"></span></button>
			<div id="help_info" class="hide-if-js">
				<h3><?php _e( 'Try one of these alternate methods.', 'secupress' ); ?></h3>
				<p><label><input type="radio" name="doubleauth_lost_method" value="backupcode" checked="checked"> <?php _e( 'Use a backup code.', 'secupress' ); ?></label></p>
				<?php if ( get_user_meta( $user->ID, 'backup_email', true ) ) { ?>
				<p><label><input type="radio" name="doubleauth_lost_method" value="backupmail"> <?php _e( 'Send a backup code on backup email.', 'secupress' ); ?></label></p>
				<?php } ?>
				<p class="submit">
					<input type="submit" id="secondary-submit" class="button button-secondary button-large button-full" value="<?php esc_attr_e( 'Use this method', 'secupress' ); ?>" />
				</p>
			</div>
		</form>
		<?php
		login_footer( 'otp' );
	} else {
		login_footer();
	}
	die();
}

add_action( 'login_footer', '__secupress_doubleauth_hideifnojs' );
function __secupress_doubleauth_hideifnojs() {

	if ( isset( $_GET['action'] ) && 'doubleauth' == $_GET['action'] ) {
	?>
	<script src="<?php echo esc_url( site_url( '/wp-includes/js/jquery/jquery.js' ) ); ?>"></script>
	<script>
	jQuery( document ).ready( function($) {
		$( "#help_info" ).hide();
		$( "#help_lost" ).click( function(e) {
			e.preventDefault();
			$(this).hide();
			$( "#help_info" ).slideDown();
		} );
	} );
	</script>
	<?php
	}
}

/**
 * Login form handling.
 * Check Mobile Authenticator app password, if user has been setup to do so.
 * @param wordpressuser
 * @return user/loginstatus
 */
add_filter( 'authenticate', '__secupress_doubleauth_otp', PHP_INT_MAX, 3 );
function __secupress_doubleauth_otp( $raw_user, $username, $password ) {

	if ( secupress_is_affected_role( 'users-login', 'double-auth', $raw_user ) && 
		secupress_doubleauth_get_user_option( 'secret', $raw_user->ID ) && secupress_doubleauth_get_user_option( 'verified', $raw_user->ID ) &&
		defined( 'XMLRPC_REQUEST' ) || defined( 'APP_REQUEST' )
	) {
		$user = get_user_by( 'login', $username );

		if ( $user && wp_check_password( $password, secupress_doubleauth_get_user_option( 'app_password', $user->ID ), $user->ID ) ) {
			return $user;
		} else {
			return new WP_Error( 'authentication_failed', __( '<strong>ERROR</strong>: The application password is incorrect.', 'secupress' ) );
		} 		 
	} 		 

	if ( ! is_wp_error( $raw_user ) && ! empty( $_POST ) ) {

		if ( secupress_is_affected_role( 'users-login', 'double-auth', $raw_user ) && 
			secupress_doubleauth_get_user_option( 'secret', $raw_user->ID ) && secupress_doubleauth_get_user_option( 'verified', $raw_user->ID )
		) {

			$token = wp_hash( wp_generate_password( 32, false ), 'nonce' );

			secupress_doubleauth_update_user_option( 'token', $token, $raw_user->ID );
			secupress_doubleauth_update_user_option( 'timeout', time() + 10 * MINUTE_IN_SECONDS, $raw_user->ID );
			$raw_user    = null;
			$rememberme  = isset( $_POST['rememberme'] );
			$redirect_to = add_query_arg( array( 'action' => 'doubleauth', 
												 'token' => $token, 
												 'rememberme' => $rememberme ), 
											wp_login_url()
										);
			wp_redirect( $redirect_to );
			die();

		}
	}

	return $raw_user;
}


/**
 * Enqueue the jQuery QRCodejs script
 */
add_action( 'admin_print_scripts-profile.php', 'secupress_doubleauth_add_jqrcode' );
function secupress_doubleauth_add_jqrcode() {
	$suffix = defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG ? '' : '.min';
    wp_enqueue_script( 'qrcode_script', plugins_url( 'inc/js/jquery.qrcode-0.12.0' . $suffix . '.js', __FILE__ ), array( 'jquery' ), '0.12.0', true );
}

/**
 * Extend personal profile page with double authentication settings.
 */
add_action( 'profile_personal_options', 'secupress_doubleauth_profile_personal_options' );
function secupress_doubleauth_profile_personal_options() {
	global $current_user;
	
	$user_id                  = $current_user->ID;
	$doubleauth_secret        = secupress_doubleauth_get_user_option( 'secret' );
	$doubleauth_backupcodes   = secupress_doubleauth_get_user_option( 'backupcodes' );
	$doubleauth_app_pass      = secupress_doubleauth_get_user_option( 'app_password' );
	$doubleauth_app_pass_info = '';


	if ( '' == $doubleauth_app_pass ) {

		$doubleauth_app_pass_info = __( '[No application password yet.]', 'secupress' );

	} elseif ( $app_pass_transient = get_site_transient( 'secupress_doubleauth_reset_app_password-' . $user_id ) ) {

		delete_site_transient( 'secupress_doubleauth_reset_app_password-' . $user_id );

		if ( $app_pass_transient ) {
			$app_pass_fmt           = '<span style="letter-spacing:1em">%s</span>';
			$app_pass_transient     = str_split( $app_pass_transient );
			$app_pass_transient[3]  = sprintf( $app_pass_fmt, $app_pass_transient[3] );
			$app_pass_transient[7]  = sprintf( $app_pass_fmt, $app_pass_transient[7] );
			$app_pass_transient[11] = sprintf( $app_pass_fmt, $app_pass_transient[11] );
			$app_pass_transient     = implode( "", $app_pass_transient );
		}
		$doubleauth_app_pass_info = $app_pass_transient;

	} else {

		$doubleauth_app_pass_info = str_repeat( '&bull;', 16 ) . __( ' (hidden for safety)', 'secupress' );

	}
	?>
	<h3 id="doubleauth_secret"><?php _e( 'Mobile Authenticator Settings', 'secupress' ); ?></h3>

	<table class="form-table">
		<tbody>
			<tr>
				<th>
					<?php _e( 'Secret Application Key', 'secupress' ); ?>
					<p class="description"><?php printf( __( 'Get a Free OTP Mobile Application on <a href="%1$s" target="_blank">Android</a> and <a href="" target="_blank">iOS</a>.', 'secupress' ), 'https://play.google.com/store/apps/details?id=org.fedorahosted.freeotp', 'https://itunes.apple.com/us/app/freeotp-authenticator/id872559395?mt=8' ); ?></p>
				</th>
				<td>
				<?php
					if ( secupress_doubleauth_get_user_option( 'verified' ) ) {
						echo '<p>' . __( 'Your account is using a double authentication.', 'secupress' ) . '</p>';
					} else {
						echo '<p>' . __( 'Your account is NOT using a double authentication.', 'secupress' ) . '</p>';
					}
				?>
					<a href="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=secupress_doubleauth_regen_secret' ), 'secupress_doubleauth_regen_secret' ); ?>" class="button button-secondary button-small">
					<?php 
					if ( secupress_doubleauth_get_user_option( 'verified' ) ) {
						_e( 'Revoke and generate a new application key', 'secupress' );
					} else {
						_e( 'Generate an application key', 'secupress' );
					}
					?>
					</a>
				</td>
			</tr>	
			<?php 

			// Display backup codes if the auth is verified (so we have backup codes)
			if ( secupress_doubleauth_get_user_option( 'verified' ) ) {
			?>
			<tr>			
				<th>
					<?php _e( 'Backup Codes', 'secupress' ); ?>
					<p class="description"><?php _e( 'When your phone is unavailable or just can\'t log in your account using the Mobile Authenticator.', 'secupress' ); ?></p>
				</th>
				<td>
					<p id="backupcodes_codes_description" data-desc="<?php echo esc_attr( sprintf( _n( 'You have %d unused code.', 'You have %d unused codes.', $backup_codes_count, 'secupress' ), 10 ) ); ?>" class="description">
					<?php
						$backup_codes_count = count( array_filter( (array) $doubleauth_backupcodes ) );
						echo esc_html( sprintf( _n( 'You have %d unused code.', 'You have %d unused codes.', $backup_codes_count, 'secupress' ), $backup_codes_count ) );
					?>
					</p>
					<div id="backupcodes_codes" class="hide-if-js">
						<ol>
						<?php
						foreach ( $doubleauth_backupcodes as $bkcode ) {
							$bkcode = $bkcode ? $bkcode : __( '-- (used)', 'secupress' );
							if ( is_numeric( $bkcode[3] ) ) {
								$bkcode = str_split( $bkcode );
								$bkcode[3] = '<span style="letter-spacing:1em">' . $bkcode[3] . '</span>';
								$bkcode = implode( "", $bkcode );
							}
							echo "<li><code>$bkcode</code></li>";
						}
						?>
						</ol>
					</div>
					<p id="backupcodes_warning" class="hidden description">
						<?php _e( 'Keep them someplace accessible, like your wallet. Each code can be used only once.<br>Before running out of backup codes, generate new ones. Only the latest set of backup codes will work.', 'secupress' ); ?>
					</p>
					<?php if ( $backup_codes_count > 0 ) { ?>
					<p id="backupcodes_show_button" class="hide-if-no-js">
						<button class="button button-secondary button-small" type="button">
							<?php _e( 'Show backup codes', 'secupress' ); ?>
						</button>
					</p>
					<?php } ?>
					<p>
						<a href="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=secupress_doubleauth_renew_backup_codes' ), 'secupress_doubleauth_renew_backup_codes' ); ?>" id="doubleauth_newcodes" class="button button-secondary button-small">
							<?php _e( 'Generate new backup codes', 'secupress' ); ?>
						</a>
					</p>
				</td>
			</tr>	
			<tr>
			<th>
				<?php _e( 'Application Password', 'secupress' ); ?>
				<p class="description">
					<?php _e( 'If an external application needs to log in your website, simply generate a secret application password.', 'secupress' ); ?>
				</p>
			</th>
				<td>
					<p>
						<code id="app_password"><?php echo $doubleauth_app_pass_info; ?></code>
						<p>
							<a href="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=secupress_doubleauth_new_app_password' ), 'secupress_doubleauth_new_app_password' ); ?>" id="doubleauth_renew_app_password" class="button button-secondary button-small" data-revoke-text="<?php esc_attr_e( 'Revoke and generate a new application password', 'secupress' ); ?>" data-generate-text="<?php esc_attr_e( 'Generate an application password', 'secupress' ); ?>">
								<?php 
								if ( ! $doubleauth_app_pass ) {
									_e( 'Generate an application password', 'secupress' );
								} else {
									_e( 'Revoke and generate a new application password', 'secupress' );
								}
								?>
							</a>
						</p>
						<p>
							<a href="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=secupress_doubleauth_delete_app_password' ), 'secupress_doubleauth_delete_app_password' ); ?>" id="doubleauth_delete_app_password" class="<?php echo $doubleauth_app_pass ? '' : 'hide-if-js'; ?> button button-secondary button-small">
								<?php _e( 'Remove the application password', 'secupress' ); ?>
							</a>
						</p>
					</p>
				</td>
			</tr>
			<?php		
			}
			?>
		</tbody>
	</table>
	<script type="text/javascript">
	jQuery( document ).ready( function($) {

		// secupress_doubleauth_new_app_password
		$( "#doubleauth_renew_app_password" ).on( "click", function(e) {
			e.preventDefault();//// swal?
			if ( confirm( '<?php echo esc_js( __( "Renewing your application password will forbid old password to work again.\nAre you sure to continue?", 'secupress' ) ); ?>' )
			) {
				$( "#app_password" ).html( '<img src="<?php echo admin_url( '/images/wpspin_light.gif' ); ?>" />' );
				var href = $(this).attr("href");
				$.get( href.replace("admin-post", "admin-ajax"), function( data ) { 
					if ( data.success ) {
						var orig = data.data;
						var code = orig.substr(0,3) + '<span style="letter-spacing:1em">' + orig[3] + '</span>' + orig.substr(4,3) + '<span style="letter-spacing:1em">' + orig[7] + '</span>' + orig.substr(8,3) + '<span style="letter-spacing:1em">' + orig[11] + '</span>' + orig.substr(12,4);
						$( "#app_password" ).html( code );
						$( "#doubleauth_delete_app_password" ).css("display", "inline-block");
						$( "#doubleauth_renew_app_password" ).text( $( "#doubleauth_renew_app_password" ).attr("data-revoke-text"));
					}
				} );
			}
		});

		// secupress_doubleauth_delete_app_password
		$( "#doubleauth_delete_app_password" ).on( "click", function(e) {
			e.preventDefault(); //// swal?
			if ( confirm( '<?php echo esc_js( __( "Deleting your application password will forbid old password to work again.\nAre you sure to continue?", 'secupress' ) ); ?>' )
			) {
				$( "#app_password" ).html( '<img src="<?php echo admin_url( '/images/wpspin_light.gif' ); ?>" />' );
				var href = $(this).attr("href");
				$.get( href.replace("admin-post", "admin-ajax" ), function( data ) { 
					if ( data.success ) {
						$( "#app_password").html( '<?php echo esc_js( __( '[No application password yet.]', 'secupress' ) ); ?>' );
						$( "#doubleauth_delete_app_password" ).hide();
						$( "#doubleauth_renew_app_password" ).text( $("#doubleauth_renew_app_password").attr("data-generate-text"));
					}
				} );
			}
		});

		// googleauthenticator_new_backup_codes
		$( "#doubleauth_newcodes" ).on( "click", function(e) {
			e.preventDefault(); //// swal
			if ( confirm( '<?php echo esc_js( __( "Renewing your backup codes will revoke all old ones.\nAre you sure to continue?", 'secupress' ) ); ?>' )
			) {
				$( '#backupcodes_codes li' ).html( '<img src="<?php echo admin_url( '/images/wpspin_light.gif' ); ?>" />' );
				var href = $(this).attr('href');
				$( '#backupcodes_codes' ).show();
				$( '#backupcodes_warning' ).show();
				$( '#backupcodes_show_button' ).hide();
				$.get( href.replace( 'admin-post', 'admin-ajax' ), function( data ) { 
					if ( data.success ) {
						$( '#backupcodes_codes_description' ).text( $( '#backupcodes_codes_description' ).data( 'desc' ) );
						var lis = '<ol>';
						for ( index in data.data ) {
							var orig = data.data[ index ];
							var code = orig.substr( 0, 3 ) + '<span style="letter-spacing:1em">' + orig[3] + '</span>' + orig.substr(4,8);
							lis += '<li><code>' + code + '</code></li>';
						} 
						lis += '</ol>';
						$('#backupcodes_codes').html( lis );
					}
				} );
			}
		});

		// backupcodes_show_button
		$( '#backupcodes_show_button' ).click( function(e) {
			e.preventDefault();
			$( this ).hide();
			$( "#backupcodes_codes" ).show();
			$( "#backupcodes_warning" ).show();
		} );

	} );
	</script>
<?php
}

add_action( 'admin_post_secupress_doubleauth_regen_secret', '__secupress_doubleauth_regen_secret_ajax_post_cb' );
function __secupress_doubleauth_regen_secret_ajax_post_cb() {

	if ( isset( $_GET['_wpnonce'] ) && wp_verify_nonce( $_GET['_wpnonce'], 'secupress_doubleauth_regen_secret' ) ) {
		
		array_map( 'secupress_doubleauth_delete_user_option', 
			array( 'verified', 'skip', 'secret', 'app_password', 'timeout', 'lasttimeslot', 'lost', 'token', 'backupcodes' )
		);

		wp_redirect( wp_get_referer() );
		die();
	} else {
		wp_nonce_ays( '' );
	}
}

add_action( 'wp_ajax_secupress_doubleauth_renew_backup_codes', '__secupress_doubleauth_renew_backup_codes_ajax_post_cb' );
add_action( 'admin_post_secupress_doubleauth_renew_backup_codes', '__secupress_doubleauth_renew_backup_codes_ajax_post_cb' );
function __secupress_doubleauth_renew_backup_codes_ajax_post_cb( $uid = 0 ) {
	global $current_user;

	if ( $uid || isset( $_GET['_wpnonce'] ) && wp_verify_nonce( $_GET['_wpnonce'], 'secupress_doubleauth_renew_backup_codes' ) ) {

		$user_id = $uid ? $uid : $current_user->ID;

		$newkeys = secupress_generate_backupcodes();

		secupress_doubleauth_update_user_option( 'backupcodes', $newkeys );

		if ( ! $uid ) {

			if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
				wp_send_json_success( $newkeys );
			} else {
				wp_redirect( wp_get_referer() );
				die();
			}

		}

	} else {

		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			wp_send_json_error();
		} else {
			wp_nonce_ays( '' );
		}

	}
}

add_action( 'wp_ajax_secupress_doubleauth_new_app_password', '__secupress_doubleauth_new_app_password_ajax_post_cb' );
add_action( 'admin_post_secupress_doubleauth_new_app_password', '__secupress_doubleauth_new_app_password_ajax_post_cb' );
function __secupress_doubleauth_new_app_password_ajax_post_cb() {
	global $current_user;

	if ( isset( $_GET['_wpnonce'] ) && wp_verify_nonce( $_GET['_wpnonce'], 'secupress_doubleauth_new_app_password' ) ) {

		$newkey = secupress_generate_password( 16, array( 'min' => true, 'maj' => false, 'num' => false ) );
		
		secupress_doubleauth_update_user_option( 'app_password', wp_hash_password( $newkey ) );
		
		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			wp_send_json_success( $newkey );
		} else {
			set_site_transient( 'secupress_doubleauth_reset_app_password-' . $current_user->ID, $newkey );
			wp_redirect( wp_get_referer() );
			die();
		}

	} else {

		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			wp_send_json_error();
		} else {
			wp_nonce_ays( '' );
		}

	}
}

add_action( 'wp_ajax_secupress_doubleauth_delete_app_password', '__secupress_doubleauth_delete_app_password_ajax_post_cb' );
add_action( 'admin_post_secupress_doubleauth_delete_app_password', '__secupress_doubleauth_delete_app_password_ajax_post_cb' );
function __secupress_doubleauth_delete_app_password_ajax_post_cb() {
	global $current_user;

	if ( isset( $_GET['_wpnonce'] ) && wp_verify_nonce( $_GET['_wpnonce'], 'secupress_doubleauth_delete_app_password' ) ) {

		secupress_doubleauth_delete_user_option( 'app_password', $current_user->ID );

		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			wp_send_json_success();
		} else {
			wp_redirect( wp_get_referer() );
			die();
		}
	} else {
		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			wp_send_json_error();
		} else {
			wp_nonce_ays( '' );
		}
	}
}

/**
 * This warnings are displayed when you ran out of auth backup codes
 *
 * @since 1.0
 */
add_action( 'admin_notices', '__secupress_doubleauth_warning_no_backup_codes' );
function __secupress_doubleauth_warning_no_backup_codes() {

	$codes = secupress_doubleauth_get_user_option( 'backupcodes' );
	if ( is_array( $codes ) && ! count( array_filter( $codes ) ) ) {
		?>
		<div class="error">
			<p>
				<b><?php echo SECUPRESS_PLUGIN_NAME; ?></b>: 
				<?php printf( __( 'You ran out of backup codes! Please <a href="%s#doubleauth_secret">renew it</a>!', 'secupress' ), get_edit_profile_url() ); ?>
			</p>
		</div>
		<?php
	}
}

/**
 * This warnings are displayed when you did not yet generate a key
 *
 * @since 1.0
 */
add_action( 'admin_notices', 'secupress_doubleauth_warning_not_set_yet' );
function secupress_doubleauth_warning_not_set_yet() {

	if ( ! secupress_doubleauth_get_user_option( 'verified' ) ) {
	?>
	<div class="error">
		<p>
			<b><?php echo SECUPRESS_PLUGIN_NAME; ?></b>:
			<?php printf( __( 'Your account requires a double authentication using a Mobile Authenticator, you have to <a href="%s#doubleauth_secret">generate an application key</a>.', 'secupress' ), get_edit_profile_url() ); ?>
		</p>
	</div>
	<?php
	}
}

add_action( 'admin_init', 'secupress_doubleauth_redirect' );
function secupress_doubleauth_redirect() {
	global $current_user, $pagenow;

	if ( 'admin-post.php' == $pagenow || 'admin-ajax.php' == $pagenow || ! is_user_logged_in() || 
		secupress_doubleauth_get_user_option( 'verified' ) || (int) secupress_doubleauth_get_user_option( 'skip' ) > time()
		) {
		return;
	}

	secupress_doubleauth_delete_user_option( 'skip', $current_user->ID );

	$args          = array();
	$args['head']  = '<script src="' . esc_url( site_url( '/wp-includes/js/jquery/jquery.js' ) ) . '"></script>' . "\n";
	$args['head'] .= '<style>.hide-if-no-js{display:none} #confirmation_code{ text-align: center; font-size: xx-large; letter-spacing: 0.5em; font-family: Courier, Arial; } ol code{font-size: large}</style>' . "\n";
	$suffix        = defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG ? '' : '.min';
	$canskip       = true;
	$step          = ! isset( $_POST['step'] ) || ! is_int( absint( $_POST['step'] ) ) || absint( $_POST['step'] ) > 4 ? 0 : absint( $_POST['step'] );

	if ( ! $step ) {
		$submit_value = __( 'Continue &#8594;', 'secupress' );
	} else {
		$submit_value = __( 'Next &#8594;', 'secupress' );
	}

	ob_start();
	?>
	<form class="wrap" action="<?php echo secupress_get_current_url( 'raw' ); ?>" method="post">
		<h1><?php _e( 'Double Authentication Setting Required', 'secupress' ); ?></h1>
		<p>
		<?php 
		switch ( $step ) {
			// No Step
			default:
				echo strip_tags( sprintf( __( 'Your account requires a double authentication using a Mobile Authenticator, you have to <a href="%s#doubleauth">generate an application key</a>.', 'secupress' ), get_edit_profile_url() ) );
				?><p class="description">
				<?php printf( __( 'Get a OTP Mobile Application on <a href="%1$s" target="_blank">Android</a> and <a href="%2$s" target="_blank">iOS</a>.', 'secupress' ), 'https://play.google.com/store/apps/details?id=org.fedorahosted.freeotp', 'https://itunes.apple.com/us/app/freeotp-authenticator/id872559395?mt=8' ); ?>
				</p>
				<?php
			break;
			
			// Step 1
			case 1:
				$doubleauth_secret = secupress_generate_key();
				secupress_doubleauth_update_user_option( 'secret', $doubleauth_secret, $current_user->ID );

				$args['head'] .= '<script src="' . esc_url( plugins_url( 'inc/js/jquery.qrcode-0.12.0' . $suffix . '.js', __FILE__ ) ) . '"></script>' . "\n";
				$args['head'] .= '<script>jQuery(document).ready( function($){ ' . "\n" .
					'$(".hide-if-no-js").show();' . "\n" .
					'var qrcode = "otpauth://totp/WordPress:"+escape("' . esc_js( get_bloginfo( 'name' ) ) . '")+"?secret=' . $doubleauth_secret . '&issuer=WordPress";' . "\n" .
					'$( "#doubleauth_qrcode" ).html( "" ).qrcode( { "render":"image", "background":"#ffffff", "size": 200, "text":qrcode } );' . "\n" .
					'$( "#doubleauth_secret" ).text( "' . $doubleauth_secret . '" ).css( "font-size", "1.5em" );' . "\n" .
					' });</script>';

				?>
				<h2><?php printf( __( 'Step %d', 'secupress' ), $step ); ?></h2>
					<code id="doubleauth_secret"><?php echo $doubleauth_secret; ?></code>
					<div class="hide-if-js">
						<span id="doubleauth_qrcode"></span>
						<br>
						<span class="description">
							<img src="https://cdn2.iconfinder.com/data/icons/touch-gestures-10/24/Mobile-Touch-128.png" todo="////">
							<p class="description hidden"><?php _e( 'You can <span class="hide-if-no-js">scan the QRCode or </span>use the key directly in your Mobile Application.', 'secupress' ); ?></p>
						</span>
					</div>
				<?php
			break;

			// Step 2 (backup codes)
			case 2:
				?>
				<h2><?php printf( __( 'Step %d', 'secupress' ), $step ); ?></h2>
				<?php

				_e( 'When your phone is unavailable or when you just can\'t log in your account using the Mobile OTP Authenticator, you will need to use one of these backup codes.', 'secupress' );

				__secupress_doubleauth_renew_backup_codes_ajax_post_cb( $current_user->ID );
				$doubleauth_backupcodes = secupress_doubleauth_get_user_option( 'backupcodes' );

				echo '<ol>';
					foreach ( $doubleauth_backupcodes as $bkcode ) {
						if ( is_numeric( $bkcode[3] ) ) {
							$bkcode = str_split( $bkcode );
							$bkcode[3] = '<span style="letter-spacing:1em">' . $bkcode[3] . '</span>';
							$bkcode = implode( "", $bkcode );
						}
						echo "<li><code>$bkcode</code></li>";
					}
					echo '</ol>';

				_e( 'Keep them someplace accessible, like your wallet. Each code can be used only once.', 'secupress' );
			break;

			// Step 3 (test & confirmation)
			case 3:
				$timeslot = false;

				if ( isset( $_POST['confirmation_code'] ) ) {
					$doubleauth_secret = secupress_doubleauth_get_user_option( 'secret' );
					$lasttimeslot      = secupress_doubleauth_get_user_option( 'lasttimeslot' );
					$timeslot          = __secupress_base32_verify( $doubleauth_secret, $_POST['confirmation_code'], $lasttimeslot );
				}

				if ( $timeslot ) {
					secupress_doubleauth_update_user_option( 'lasttimeslot', $timeslot, $current_user->ID );
					secupress_doubleauth_update_user_option( 'verified', 1, $current_user->ID );

					$submit_value = __( 'Close', 'secupress' );
					$canskip      = false;

					?>
					<h2><?php _e( 'Done!', 'secupress' ); ?></h2>
					<img todo="////" src="data:image/png;base64,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">
					<p>
					<?php
						_e( 'You account is now using a Double Authentication, congratulations!', 'secupress' );
					?>
					</p>
					<em><?php _e( 'If you need to set an application password, you can do it in your profile.', 'secupress' ); ?></em>
					<?php
				} else {
					$args['head'] .= '<script>jQuery(document).ready( function($){ d = document.getElementById("confirmation_code"); d.focus(); d.select(); });</script>' . "\n";

					?><h2><?php printf( __( 'Step %d', 'secupress' ), $step ); ?></h2>
					<p>
					<?php
						_e( 'Now you need to confirm your double authentication setting, please enter the code provided by your Mobile OTP Application', 'secupress' );
					?>
					</p>
					<p>
						<input type="text" name="confirmation_code" id="confirmation_code" maxlength="6" placeholder="******">
					<?php
					if ( isset( $_POST['confirmation_code'] ) ) {
						_e( 'Invalid Confirmation Code', 'secupress' );
						$submit_value = __( 'Retry &#8594;', 'secupress' );
					}
					--$step;
				}
				?></p><?php
			break;

			// Just redirect on the referer, it's ok now
			case 4:
				wp_safe_redirect( urldecode( wp_get_referer() ) );
				die();
			break;

		}
		++$step;
		?>
		</p>
		<input type="hidden" name="step" value="<?php echo $step; ?>">
		<input type="hidden" name="_wp_http_referer" value="<?php echo urlencode( secupress_get_current_url( 'raw' ) ); ?>">
		<?php
		submit_button( $submit_value, 'primary', $name = 'submit' );

		if ( $canskip ) {
		?>
		<p>
			<a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=secupress_doubleauth_skip' ), 'secupress_doubleauth_skip' ) ); ?>">
				<small><?php _e( 'Skip this, i\'ll do it later in my profile,<br>but remind me in 7 days.', 'secupress' ); ?></small>
			</a>
		</p>
		<?php 
		}

		?>
	</form>
	<?php
	$content = ob_get_contents();
	$title   = __( 'Double Authentication Account Settings', 'secupress' );
	ob_clean();

	// Display the correct informations
	secupress_action_page( $title, $content, $args );
}

add_action( 'admin_post_secupress_doubleauth_skip', '__secupress_doubleauth_skip_ajax_post_cb' );
function __secupress_doubleauth_skip_ajax_post_cb() {
	global $current_user;

	if ( ! isset( $_GET['_wpnonce'] ) ) {
		wp_nonce_ays( '' );
	}

	check_admin_referer( 'secupress_doubleauth_skip' );

	array_map( 'secupress_doubleauth_delete_user_option', 
		array( 'verified', 'skip', 'secret', 'app_password', 'timeout', 'lasttimeslot', 'lost', 'token', 'backupcodes' )
	);
	secupress_doubleauth_update_user_option( 'skip', time() + ( 7 * DAY_IN_SECONDS ) );

	wp_safe_redirect( wp_get_referer() );
	die();
}

/*
TODO :
multiple app password
*/