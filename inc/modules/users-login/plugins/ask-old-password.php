<?php
/**
 * Module Name: Ask for old password
 * Description: Users must provide their old password when they want to change it in their profile page.
 * Main Module: users_login
 * Author: SecuPress
 * Version: 1.0
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );


add_action( 'admin_init', 'secupress_oldpassword_init' );
/**
 * Plugin init.
 *
 * @since 1.0
 * @author Grégory Viguier
 */
function secupress_oldpassword_init() {
	if ( ! secupress_is_affected_role( 'users-login', 'password-policy', wp_get_current_user() ) ) {
		return;
	}

	add_filter( 'show_password_fields',       'secupress_oldpassword_prepare_field', PHP_INT_MAX );
	add_action( 'user_profile_update_errors', 'secupress_oldpassword_check_old_password', 10, 3 );
}


/**
 * Start the process that will add the password field.
 * Basically it does a `ob_start()` and launches the hooks that will `ob_get_clean()`.
 *
 * @since 1.0
 *
 * @param (bool) $show Whether to show the password fields. Default true.
 *
 * @return (bool) Unchanged value of `$show`.
 */
function secupress_oldpassword_prepare_field( $show ) {
	global $pagenow;

	if ( $show && ( 'profile.php' === $pagenow || 'user-edit.php' === $pagenow ) ) {
		ob_start();

		add_action( 'show_user_profile', 'secupress_oldpassword_add_field', -1 );
		add_action( 'edit_user_profile', 'secupress_oldpassword_add_field', -1 );
	}

	return $show;
}


/**
 * End the process that will add the password field.
 * Get the password fields with `ob_get_clean()` and add the new field.
 *
 * @since 1.0
 */
function secupress_oldpassword_add_field() {
	$before = ob_get_clean();
	$after  = '';
	$sep    = '<tr class="user-sessions-wrap hide-if-no-js">';

	// Let's start the hellish stuff... =_=.
	if ( secupress_wp_version_is( '4.3' ) ) {
		$field = '
<tr class="user-pass-old-wrap hide-if-js">
	<th scope="row"><label for="pass-old">' . __( 'Current Password', 'secupress' ) . '</label></th>
	<td>
		<input name="pass-old" type="password" id="pass-old" class="regular-text" value="" autocomplete="off" />
		<p class="description">' . __( 'Type your current password', 'secupress' ) . '</p>
		<script type="text/javascript">
		(function($) {
			// Move the field.
			var pass1 = $( ".user-pass1-wrap .wp-pwd, .secupress-user-pass1-wrap .wp-pwd" ),
				field;
			if ( pass1.length ) {
				field = "<div class=\"wp-pwd hide-if-js\"><label for=\"pass-old\">' . sprintf( __( '%s:', 'secupress' ), __( 'Type your current password', 'secupress' ) ) . '</label><br/><input name=\"pass-old\" type=\"password\" id=\"pass-old\" class=\"regular-text\" value=\"\" autocomplete=\"off\" /></div>";
				$( ".user-pass-old-wrap" ).remove();
				pass1.last().after( field );
			} else {
				$( ".user-pass-old-wrap" ).removeClass( ".hide-if-js" );
			}
		} )(jQuery);</script>
	</td>
</tr>';
	} elseif ( secupress_wp_version_is( '4.1' ) ) {
		$field = '
<tr class="user-pass-old-wrap">
	<th scope="row"><label for="pass-old">' . __( 'Current Password', 'secupress' ) . '</label></th>
	<td>
		<input name="pass-old" type="password" id="pass-old" class="regular-text" size="16" value="" autocomplete="off" />
		<p class="description">' . __( 'Type your current password', 'secupress' ) . '</p>
	</td>
</tr>';
	} elseif ( secupress_wp_version_is( '3.8' ) ) {
		$field = '
<tr class="user-pass-old-wrap">
	<th scope="row"><label for="pass-old">' . __( 'Current Password', 'secupress' ) . '</label></th>
	<td>
		<input name="pass-old" type="password" id="pass-old" class="regular-text" size="16" value="" autocomplete="off" /><br />
		<span class="description">' . __( 'Type your current password', 'secupress' ) . '</span>
	</td>
</tr>';
	} else {
		$field = '
<tr class="user-pass-old-wrap">
	<th scope="row"><label for="pass-old">' . __( 'Current Password', 'secupress' ) . '</label></th>
	<td>
		<input name="pass-old" type="password" id="pass-old" size="16" value="" autocomplete="off" /><br />
		<span class="description">' . __( 'Type your current password', 'secupress' ) . '</span>
	</td>
</tr>';
	}

	if ( false !== strpos( $before, $sep ) ) {

		$before = explode( $sep, $before, 2 );
		$after  = ( ! empty( $before[1] ) ? $sep : '' ) . $before[1];
		$before = $before[0];

	} elseif ( preg_match( '@^(.*</tr>)(\s*</table>\s*)$@s', $before, $matches ) ) {

		$before = $matches[1];
		$after  = $matches[2];

	}

	echo $before . $field . $after;
}


/**
 * When a user submits a new password, check the old one is provided and correct.
 * If not, trigger an error.
 *
 * @since 1.0
 *
 * @param (object) $errors WP_Error object, passed by reference.
 * @param (bool)   $update Whether this is a user update.
 * @param (object) $user   WP_User object, passed by reference.
 */
function secupress_oldpassword_check_old_password( $errors, $update, &$user ) {
	if ( empty( $user->user_pass ) || ! isset( $user->ID ) ) {
		return;
	}

	$old_pass = isset( $_POST['pass-old'] ) ? $_POST['pass-old'] : ''; // WPCS: CSRF ok.
	$old_hash = get_userdata( $user->ID )->user_pass;

	if ( ! $old_pass || ! wp_check_password( $old_pass, $old_hash, $user->ID ) ) {
		$errors->add( 'pass', __( '<strong>ERROR</strong>: Please enter your current password.', 'secupress' ), array( 'form-field' => 'pass-old' ) );
	}
}
