<?php
/**
 * Module Name: Anti-Phishing Code
 * Description: A digit code will be included in every email from this website, ensuring its authenticity and safeguarding against phishing
 * Main Module: users_login
 * Author: SecuPress
 * Version: 2.2.6
 */


add_action( 'profile_personal_options', 'secupress_antiphishing_profile_personal_options' );
/**
 * Extend personal profile page with double authentication settings.
 *
 * @since 2.2.6
 * @author Julio Potier
 */
function secupress_antiphishing_profile_personal_options() {
	global $current_user;
	$digit = get_user_option( 'secupress_antiphishingcode', $current_user->ID );
	?>
	<table class="form-table" id="antiphishingcode">
		<tbody>
			<tr>
				<th>
					<?php _e( 'Anti-Phishing Code', 'secupress' ); ?>
				</th>
				<td style="vertical-align:top;">
					<input type="number" maxlength="9" name="antiphishingcode" value="<?php echo esc_attr( $digit ); ?>">
					<p class="description"><?php
						_e( 'Choose a digit code to be included in every email from this website, ensuring its authenticity and safeguarding against phishing.', 'secupress' );
						echo '<br>';
						_e( 'It can be anything, your phone number, your postal code, you birth date, your favorite math sequence&hellip;', 'secupress' );
					?></p>
				</td>
			</tr>
		<tbody>
	</table>
	<?php
}

add_action( 'personal_options_update', 'secupress_antiphishing_save_profile_settings');
/**
 * Save some meta data related to antiphishing code
 *
 * @since 2.2.6
 * @author Julio Potier
 * 
 * @param (int) $user_id
 **/
function secupress_antiphishing_save_profile_settings( $user_id ) {
	if ( isset( $_POST['antiphishingcode'] ) ) {
		$digit = is_numeric( $_POST['antiphishingcode'] ) ? substr( $_POST['antiphishingcode'], 0, 9 ) : false;
		if ( ! $digit ) {
			return;
		}
		update_user_option( $user_id, 'secupress_antiphishingcode', $digit );
	}
}

add_action( 'admin_head', 'secupress_antiphishing_notice' );
/**
 * Display the notice for the users so they know they can add the code.
 *
 * @since 2.2.6
 * @author Julio Potier
 **/
function secupress_antiphishing_notice() {
	global $current_user;
	if ( ! user_can( $current_user, 'exist' ) ) {
		return;
	}
	$digit = get_user_option( 'secupress_antiphishingcode', $current_user->ID );
	if ( ! secupress_notice_is_dismissed( 'antiphishingcode' ) && ! $digit ) {
		$message = sprintf( __( 'You can now set up an Anti-Phishing Code to protect yourself from phishing attempts on this website. <a href="%s">Set my code now.</a>', 'secupress' ), get_edit_profile_url() . '#antiphishingcode' );
		secupress_add_notice( $message, 'updated', 'antiphishingcode' );
	}
}

add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_antiphishing_deactivation' );
add_action( 'secupress.plugins.deactivation', 'secupress_antiphishing_deactivation' );
/**
 * On deactivation, delete anything related to antiphishing code for any user
 *
 * @since 2.2.6
 * @author Julio Potier
 */
function secupress_antiphishing_deactivation() {
	global $wpdb;

	delete_metadata( 'user', false, $wpdb->prefix . 'secupress_antiphishingcode',  false, true );
}

add_filter( 'wp_mail', 'secupress_antiphishingcode_mail' );
/**
 * Adds the users code to its email
 * 
 * @since 2.2.6
 * @author Julio Potier
 * 
 * @param (array) $atts
 * 
 * @return (array) $atts
 **/
function secupress_antiphishingcode_mail( $atts ) {
	$admin_email = get_option( 'admin_email' );
	$atts_to     = is_array( $atts['to'] ) ? reset( $atts['to'] ) : $atts['to'];
	$user        = secupress_get_user_by( $atts_to );
	if ( ! secupress_is_user( $user ) && $atts_to !== $admin_email ) {
		return $atts;
	}
	if ( secupress_is_user( $user ) ) { // user
		$digit   = get_user_option( 'secupress_antiphishingcode', $user->ID );
	} else { // admin_email
		$digit   = secupress_get_module_option( 'antiphishing_admin_code', false, 'antispam' );
	}
	$digit       = is_numeric( $digit ) ? substr( $digit, 0, 9 ) : false;
	if ( ! $digit ) {
		return $atts;
	}
	$text             = sprintf( __( '[Anti-Phishing Code:%s]', 'secupress' ), (int) $digit );
	// $atts['subject'] .= ' ' . $text; //// cannot do it!?? why!
	$atts['message'] .= "\n\n" . $text;

	return $atts;
}

// add_filter( 'wp_new_user_notification_email', 'secupress_antiphishingcode_new_user' ); //// TBD
/**
 * Add your message for any new user
 *
 * @since 2.2.6
 * @author Julio Potier
 * 
 * @param (array) $wp_new_user_notification_email
 * 
 * @return (array) $wp_new_user_notification_email
 **/
function secupress_antiphishingcode_new_user( $wp_new_user_notification_email ) {
	$wp_new_user_notification_email['message'] .= "\n\n" . __( '[Anti-Phishing: You can setup a personal code for more email security in your profile.]', 'secupress' );
	return $wp_new_user_notification_email;
}