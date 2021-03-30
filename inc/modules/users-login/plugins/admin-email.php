<?php
/**
 * Module Name: Lock Admin Email
 * Description: Prevent future modification of the admin email
 * Main Module: users_login
 * Author: SecuPress
 * Version: 2.0
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );
/** --------------------------------------------------------------------------------------------- */
/** ACTIVATION / DEACTIVATION =================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( 'secupress.modules.activate_submodule_' . basename( __FILE__, '.php' ), 'secupress_wpconfig_adminemail_activation' );
add_action( 'secupress.plugins.activation', 'secupress_wpconfig_adminemail_activation' );
/**
 * On module activation, remove the define.
 *
 * @since 2.0
 * @author Julio Potier
 */
function secupress_wpconfig_adminemail_activation() {
	secupress_wpconfig_modules_activation( 'adminemail' );
}


add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_wpconfig_adminemail_deactivation' );
add_action( 'secupress.plugins.deactivation', 'secupress_wpconfig_adminemail_deactivation' );
/**
 * On module deactivation, maybe put the constant back.
 *
 * @since 2.0
 * @author Julio Potier
 */
function secupress_wpconfig_adminemail_deactivation() {
	secupress_wpconfig_modules_deactivation( 'adminemail' );
}

add_filter( 'pre_option_admin_email', 'secupress_lock_admin_email_option' );
add_filter( 'pre_option_new_admin_email', 'secupress_lock_admin_email_option' );
/**
 * Lock the admin email from our constant set on module activation only
 *
 * @since 2.0
 * @author Julio Potier
 *
 * @return (string) The slug of the default role
 **/
function secupress_lock_admin_email_option( $email ) {
	$email = defined( 'SECUPRESS_LOCKED_ADMIN_EMAIL' ) ? SECUPRESS_LOCKED_ADMIN_EMAIL : $email;
	/**
	* Filter the admin email
	* @param (string) $email
	*/
	return apply_filters( 'secupress.plugin.admin_email', $email );
}


add_action( 'admin_head-options-general.php', 'secupress_disable_admin_email_input' );
/**
 * Add JS/CSS to prevent UI manipulation
 *
 * @since 2.0
 * @author Julio Potier
 *
 **/
function secupress_disable_admin_email_input() {
	$i18n = esc_js( __( 'Disabled for security reasons.', 'secupress' ) );
?>
	<script>
		jQuery( document ).ready( function($){
			$('#new_admin_email').attr('disabled','disabled').addClass('disabled').after( ' <span class="secupress_disable_select"><?php echo $i18n; ?></span> ' );
		} );
	</script>
<?php
}
