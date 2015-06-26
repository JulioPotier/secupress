<?php
/*
Module Name: Profile Protect
Description: Ask the user's password to enter in their profile page
Main Module: users_login
Author: SecuPress
Version: 1.0
*/

add_action( 'user_edit_form_tag', 'secupress_shortcut_profile', PHP_INT_MAX );
function secupress_shortcut_profile() {
	if ( IS_PROFILE_PAGE ) {
		if ( false === get_site_transient( 'secupress_profile_check_password_' . get_current_user_id() ) ) {
			?>>
			<div style="-webkit-box-shadow: 0 1px 3px rgba(0, 0, 0, 0.13);box-shadow: 0 1px 3px rgba(0, 0, 0, 0.13); background: #FFF;padding: 5px 20px;width: 320px;">
			<h3><?php _e( 'Profile Security', 'secupress' ); ?></h3>
			<p class="description">
				<?php _e( 'For security measures, you need to enter your password again to edit your profile settings.<br>Once done, you will have <b>only 5 minutes</b>, then you will have to do it again.', 'secupress' ); ?>
			</p>
			<p>
				<label for="user_pass"><b><?php _e('Password') ?></b><br />
				<input type="password" name="pwd" id="user_pass" class="input text" style="width:100%" value="" size="20" /></label>
			</p>
			<input type="hidden" name="from" value="secupress" />
			<input type="hidden" name="action" value="update" />
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
}

add_action( 'check_passwords', 'secupress_profile_check_password' );
function secupress_profile_check_password() {
	if ( false === get_site_transient( 'secupress_profile_check_password_' . get_current_user_id() ) ) {
		global $current_user;
		if ( isset( $_POST['pwd'], $_POST['_wpnonce'], $_POST['user_id'], $_POST['from'] ) &&
			'secupress' == $_POST['from'] && get_current_user_id() == $_POST['user_id'] && wp_verify_nonce( $_POST['_wpnonce'], 'update-user_' . get_current_user_id() ) &&
			! is_wp_error( wp_authenticate_username_password( null, $current_user->user_login, $_POST['pwd'] ) )
		) {
			set_site_transient( 'secupress_profile_check_password_' . $_POST['user_id'], '1', 5 * MINUTE_IN_SECONDS );
			wp_redirect( get_edit_profile_url() );
			die();
		} else {
			wp_nonce_ays( '' );
		}
	}
}
