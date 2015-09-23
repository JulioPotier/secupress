<?php
/*
Module Name: Page Protect
Description: Ask the user's password to enter in their some pages (need hooks to work)
Main Module: sensitive_data
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

/*
ajouter ici un check sur l'existance du hook load- screen_id et la fonction ^
et dans le plugin de profil il vérifie le sien
*/
function secupress_shortcut_settings() {
	if ( is_admin() && is_user_logged_in() && false === get_site_transient( 'secupress_check_password_' . get_current_user_id() ) ) {
		if ( isset( $_GET['error'] ) ) {
			$_SERVER['REQUEST_URI'] = remove_query_arg( array( 'error' ), $_SERVER['REQUEST_URI'] );
		}
		require_once( ABSPATH . 'wp-admin/admin-header.php' );
		?>
		<h1><?php echo SECUPRESS_PLUGIN_NAME; ?></h1>
		<div style="-webkit-box-shadow: 0 1px 3px rgba(0, 0, 0, 0.13);box-shadow: 0 1px 3px rgba(0, 0, 0, 0.13); background: #FFF;padding: 5px 20px;width: 320px;">
			<form id="your-profile" action="<?php echo admin_url( 'admin-post.php' ); ?>" method="post" novalidate="novalidate">
				<h3><?php _e( 'Page Access Security', 'secupress' ); ?></h3>
				<p class="description">
					<?php _e( 'For security measures, you need to enter your password again to access to this page.<br>Once done, you will have <b>only 5 minutes</b>, then you will have to do it again.', 'secupress' ); ?>
				</p>
				<p>
					<label for="user_pass" style="display:block"><b><?php _e('Password') ?></b><br />
					<input type="password" name="pwd" id="user_pass" class="input text" style="width:100%" value="" size="20" /></label>
				</p>
				<input type="hidden" name="action" value="secupress_check_password" />
				<input type="hidden" name="user_id" id="user_id" value="<?php echo get_current_user_id(); ?>" />
				<?php 
				wp_nonce_field( 'update-user_' . get_current_user_id() );
				?>
				<p style="text-align:right">
				<?php
				submit_button( __( 'Continue' ),'primary', 'submit', 0 );
				?>
				</p>
			</form>
		</div>
		<script type="text/javascript">
			try{document.getElementById('user_pass').focus();}catch(e){}
			if(typeof wpOnload=='function')wpOnload();
		</script>			
		<?php
		include( ABSPATH . 'wp-admin/admin-footer.php'); 
		die();
	}
}

add_action( 'admin_post_secupress_check_password', 'secupress_protect_check_password' );
function secupress_protect_check_password() {
	if ( false === get_site_transient( 'secupress_check_password_' . get_current_user_id() ) ) {
		global $current_user;
		if ( isset( $_POST['pwd'], $_POST['_wpnonce'], $_POST['user_id'] ) &&
			get_current_user_id() == $_POST['user_id'] && wp_verify_nonce( $_POST['_wpnonce'], 'update-user_' . get_current_user_id() ) &&
			! is_wp_error( wp_authenticate_username_password( null, $current_user->user_login, $_POST['pwd'] ) )
		) {
			set_site_transient( 'secupress_check_password_' . $_POST['user_id'], '1', 5 * MINUTE_IN_SECONDS );
			wp_safe_redirect( wp_get_referer() );
			die();
		} else {
			wp_nonce_ays( '' );
		}
	}
}
