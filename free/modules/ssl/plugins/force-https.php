<?php
/**
 * Module Name: Force HTTPS
 * Description: Force HTTPS for login, wp-admin, home, and site URLs
 * Main Module: ssl
 * Author: Julio Potier
 * Version: 2.2.6
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );


/** --------------------------------------------------------------------------------------------- */
/** ACTIVATION / DEACTIVATION =================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( 'secupress.modules.activate_submodule_' . basename( __FILE__, '.php' ), 'secupress_ssl_force_https_activation' );
add_action( 'secupress.plugins.activation', 'secupress_ssl_force_https_activation' );
/**
 * On module activation, remove the define.
 *
 * @since 2.2.6
 * @author Julio Potier
 */
function secupress_ssl_force_https_activation() {
	global $is_apache, $is_nginx, $is_iis7;

	if ( secupress_is_https_supported() ) {
		secupress_update_urls_to_https();
		secupress_wpconfig_modules_activation( 'force_https' );
		// Update the URLs only if we changed this.
		if ( secupress_is_submodule_active( 'wordpress-core', 'wp-config-constant-locations' ) ) {
			secupress_wpconfig_modules_activation( 'locations', true );
		}
	}
}

add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_ssl_force_https_deactivation' );
add_action( 'secupress.plugins.deactivation', 'secupress_ssl_force_https_deactivation' );
/**
 * On module activation, remove the define.
 *
 * @since 2.2.6
 * @author Julio Potier
 */
function secupress_ssl_force_https_deactivation() {
	secupress_wpconfig_modules_deactivation( 'force_https' );
}

add_action( 'admin_head-options-general.php', 'secupress_ssl_force_https_remove_urls_choices' );
/**
 * Disable the SITEURL and HOME input fields
 *
 * @since 2.2.6
 * @author Julio Potier
 *
 **/
function secupress_ssl_force_https_remove_urls_choices() {
	$i18n = esc_html__( 'Disabled for security reasons', 'secupress' );
?>
	<script type="text/javascript">
		jQuery( document ).ready( function($){
			$('#siteurl, #home').attr('disabled','disabled').addClass('disabled').after( '<span class="secupress_disable_select"><?php echo $i18n; ?></span> ' );
		} );
	</script>
<?php
}
