<?php
/**
 * Module Name: Lock Membership
 * Description: Prevent future modification of the membership status
 * Main Module: users_login
 * Author: SecuPress
 * Version: 2.0
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

/**
 * Lock the membership from our constant set on module activation only
 *
 * @since 2.0
 * @author Julio Potier
 *
 * @return (string) The membership status
 **/
add_filter( 'pre_option_users_can_register', '__return_zero' );

add_action( 'admin_head-options-general.php', 'secupress_disable_membership_box' );
/**
 * Add JS/CSS to prevent UI manipulation
 *
 * @since 2.0
 * @author Julio Potier
 *
 **/
function secupress_disable_membership_box() {
	$i18n = esc_js( __( 'Disabled for security reasons.', 'secupress' ) );
?>
	<script>
		jQuery( document ).ready( function($){
			$('#users_can_register').attr('disabled','disabled').addClass('disabled').parent().css('color','#a7aaad').after( ' <span class="secupress_disable_select"><?php echo $i18n; ?></span> ' );
		} );
	</script>
<?php
}
