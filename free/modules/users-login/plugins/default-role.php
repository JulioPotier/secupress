<?php
/**
 * Module Name: Lock Default Role
 * Description: Prevent future modification of the default subcription role
 * Main Module: users_login
 * Author: SecuPress
 * Version: 2.0
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

add_filter( 'pre_option_default_role', 'secupress_lock_default_role_option' );
/**
 * Lock the default role from our constant set on module activation only
 *
 * @since 2.0
 * @author Julio Potier
 *
 * @return (string) The slug of the default role
 **/
function secupress_lock_default_role_option() {
	$role       = defined( 'SECUPRESS_LOCKED_DEFAULT_ROLE' ) ? SECUPRESS_LOCKED_DEFAULT_ROLE : secupress_get_module_option( 'blacklist-logins_default-role' );
	$roles      = new WP_Roles();
	$roles      = $roles->get_names();
	$valid_role = in_array( $role, array_keys( $roles ) ) && ! isset( secupress_get_forbidden_default_roles()[ $role ] );
	if ( $valid_role ) {
		/**
		* Filter the default role for WP if found
		* @param (string) $role
		*/
		return apply_filters( 'secupress.plugin.lock_default_role', $role );
	}
	/**
	* Filter the default role for WP if empty
	* @param (string) 'subscriber'
	*/
	return apply_filters( 'secupress.plugin.lock_default_role.empty', 'subscriber' );
}


add_action( 'admin_head-options-general.php', 'secupress_disable_role_select' );
/**
 * Add JS/CSS to prevent UI manipulation
 *
 * @since 2.0
 * @author Julio Potier
 *
 **/
function secupress_disable_role_select() {
	$i18n = esc_js( __( 'Disabled for security reasons.', 'secupress' ) );
?>
	<script>
		jQuery( document ).ready( function($){
			$('#default_role').attr('disabled','disabled').addClass('disabled').after( ' <span class="secupress_disable_select"><?php echo $i18n; ?></span> ' );
		} );
	</script>
<?php
}
