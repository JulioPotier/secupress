<?php
/**
 * Module Name: Prevent Site URL Relocation
 * Description: Set the constant <code>RELOCATE</code> from the <code>wp-config.php</code> file to <code>false</code> and force WP_SITEURL and WP_HOME constants too.
 * Main Module: wordpress_core
 * Author: SecuPress
 * Version: 2.0
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** ACTIVATION / DEACTIVATION =================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( 'secupress.modules.activate_submodule_' . basename( __FILE__, '.php' ), 'secupress_wpconfig_relocate_activation' );
add_action( 'secupress.plugins.activation', 'secupress_wpconfig_relocate_activation' );
/**
 * On module activation, remove the define.
 *
 * @since 2.0
 * @author Julio Potier
 */
function secupress_wpconfig_relocate_activation() {
	secupress_wpconfig_modules_activation( 'locations' );
}


add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_wpconfig_relocate_deactivation' );
add_action( 'secupress.plugins.deactivation', 'secupress_wpconfig_relocate_deactivation' );
/**
 * On module deactivation, maybe put the constant back.
 *
 * @since 2.0
 * @author Julio Potier
 */
function secupress_wpconfig_relocate_deactivation() {
	secupress_wpconfig_modules_deactivation( 'locations' );
}

add_action( 'admin_head-options-general.php', 'secupress_remove_urls_choices' );
/**
 * Disable the SITEURL and HOME input fields
 *
 * @since 2.0
 * @author Julio Potier
 *
 **/
function secupress_remove_urls_choices() {
	$i18n = esc_html__( 'Disabled for security reasons', 'secupress' );
?>
	<script type="text/javascript">
		jQuery( document ).ready( function($){
			$('#siteurl, #home').attr('disabled','disabled').addClass('disabled').after( '<span class="secupress_disable_select"><?php echo $i18n; ?></span> ' );
		} );
	</script>
<?php
}
