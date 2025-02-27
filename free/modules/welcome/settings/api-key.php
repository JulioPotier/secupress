<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

// Add the form manually.
add_action( 'secupress.settings.before_section_secupress_display_apikey_options', array( $this, 'print_open_form_tag' ) );
add_action( 'secupress.settings.after_section_secupress_display_apikey_options', array( $this, 'print_close_form_tag' ) );

$this->set_current_section( 'secupress_display_apikey_options' );
$this->add_section( __( 'License Validation', 'secupress' ) );

add_filter( 'secupress.settings.section-secupress_display_apikey_options.submit_button_args', 'secupress_submit_button_title_for_secupress_display_apikey_options' );
/**
 * Filter the submit button for the licence.
 *
 * @since 1.4.3
 *
 * @return (array) $args
 * @author Julio Potier
 * @param (array) $args Contains the attributes and stuff to create a submit button.
 **/
function secupress_submit_button_title_for_secupress_display_apikey_options( $args ) {
	$values = get_site_option( SECUPRESS_SETTINGS_SLUG );
	$label  = __( 'License Activation', 'secupress' );
	$before = '';

	if ( is_array( $values ) && ! empty( $values['consumer_email'] ) && ! empty( $values['consumer_key'] ) ) {
		if ( empty( $values['site_is_pro'] ) ) {
			$before = '<p style="color:#CB234F">' . __( 'Your License Key is inactive or invalid.', 'secupress' ) . '</p>';
		} else {
			$label  = __( 'Deactivate the license', 'secupress' );
		}
	}

	$args['before'] = $before;
	$args['label']  = $label;

	return $args;
}

$settings   = get_site_option( SECUPRESS_SETTINGS_SLUG );
$disabled   = is_array( $settings ) && ! empty( $settings['consumer_email'] ) && ! empty( $settings['consumer_key'] ) && ! empty( $settings['site_is_pro'] );
$value      = false;
$attributes = array(
	'required'      => 'required',
	'aria-required' => 'true',
	'autocomplete'  => 'off',
);
if ( $disabled ) {
	$attributes['readonly'] = true;
	$value = str_repeat( '&bull;', 22 );
}
if ( ! secupress_has_pro() ) {
	$this->add_field( array(
		'type'         => 'html',
		'label_for'    => 'got-license',
		'value'        => '<button type="button" class="button secupress-button-primary secupress-button-big" id="got-license">' . __( 'I already got a license', 'secupress' ) . '</button>',
		'helpers'      => array(
			array(
				'type'        => 'description',
				'description' => __( 'You will need your email address and<br>license key from your pro account.', 'secupress' ),
			),
		),
	) );
	$this->add_field( array(
		'type'         => 'html',
		'label_for'    => 'need-license',
		'value'        => sprintf( '<a target="_blank" href="%s" class="button secupress-button-tertiary secupress-button-big" id="need-license">', trailingslashit( set_url_scheme( SECUPRESS_WEB_MAIN, 'https' ) ) . _x( 'pricing', 'link to website (Only FR or EN!)', 'secupress' ) ) . __( 'I need to purchase a license', 'secupress' ) . '</a>',
		'helpers'      => array(
			array(
				'type'        => 'description',
				'description' => sprintf( __( 'Unlock <strong>all Pro features</strong> by purchasing a license for just <strong>%1$s</strong> using the coupon code %2$s!', 'secupress' ), _x( '55$', '55$ for non FR languages, 48€ for FR, nothing else.', 'secupress' ), secupress_code_me( _x( 'WELCOME55', 'WELCOME55 is for $, BIENVENUE48 is for €', 'secupress' ) ) ),
			),
		),
	) );
	$this->add_field( array(
		'type'         => 'html',
		'label_for'    => 'dontmindme',
		'value'        => '<script>jQuery( document ).ready( function($) { 
								$(".secupress-setting-row_consumer_email,.secupress-setting-row_consumer_key,.secupress-setting-row_dontmindme").hide();
								$("#secupress_display_apikey_options_submit").parent().hide();
								$("#got-license").on("click", function(e){
									$(".secupress-setting-row_got-license,.secupress-setting-row_need-license").hide();
									$(".secupress-setting-row_consumer_email,.secupress-setting-row_consumer_key").show();
									$("#secupress_display_apikey_options_submit").parent().show();
									});
		 					} );</script>',
	) );
}

$this->add_field( array(
	'title'        => __( 'Email Address', 'secupress' ),
	'label_for'    => 'consumer_email',
	'type'         => 'email',
	'attributes'   => $attributes,
	'value'        => defined( 'SECUPRESS_API_EMAIL' ) ? esc_attr( SECUPRESS_API_EMAIL ) : secupress_get_consumer_email(),
	'helpers'      => array(
		array(
			'type'        => 'help',
			'description' => __( 'The email address linked with your Pro account.', 'secupress' ),
		),
	),
) );


$this->add_field( array(
	'title'        => __( 'License Key', 'secupress' ),
	'label_for'    => 'consumer_key',
	'type'         => 'text',
	'attributes'   => $attributes,
	'value'        => $value,
	'value'        => defined( 'SECUPRESS_API_KEY' ) ? esc_attr( SECUPRESS_API_KEY ) : $value,
	'helpers'      => array(
		array(
			'type'        => 'help',
			'description' => __( 'The license key linked with your Pro account.', 'secupress' ),
		),
	),
) );


$license   = secupress_get_option( 'license' );
$helper    = 'help';
$need_more = '';
if ( secupress_is_pro() && $license ) {
	if ( 0 === $license['limit'] ) { // Unlimited.
		$sites_number = sprintf( __( '%d / unlimited', 'secupress' ), (int) $license['count'] );
	} else {
		$need_more    = sprintf( _n( 'Need more than %1$d site?<br><a href="%2$s">Just ask for more!</a>', 'Need more than %1$d sites?<br><a href="%2$s">Just ask for more!</a>', $license['limit'], 'secupress' ), $license['limit'], trailingslashit( set_url_scheme( SECUPRESS_WEB_MAIN, 'https' ) ) . _x( 'pricing', 'link to website (Only FR or EN!)', 'secupress' ) );
		$sites_number = sprintf( _n( '%1$d / %2$d site', '%1$d / %2$d sites', $license['count'], 'secupress' ), (int) $license['count'], (int) $license['limit'] );
	}
} else {
	$sites_number = _x( 'Free', 'as in "Free License"', 'secupress' );
	$license      = [ 'status' => false ];
}

ob_start();
?>
<p>
	<strong><?php _e( 'License:', 'secupress' ); ?></strong>
	<code><strong><?php echo $sites_number; ?></strong></code>
	<br>
	<strong><?php _e( 'Status:', 'secupress' ); ?></strong>
	<?php
	switch ( $license['status'] ) {
		case 'active':
		case 'inactive':
			echo '<span class="dashicons dashicons-yes"></span>&nbsp;' . _x( 'Active', 'a license', 'secupress' );
		break;
		case 'expired':
			$need_more = __( 'Expired Licenses<br>cannot access Pro Features!', 'secupress' );
			$helper    = 'warning';
			echo '<span class="dashicons dashicons-clock"></span>&nbsp;' . _x( 'Expired', 'a license', 'secupress' );
		break;
		case 'disabled':
			echo '<span class="dashicons dashicons-dismiss"></span>&nbsp;' . _x( 'Disabled', 'a license', 'secupress' );
		break;
		default: echo '–';
	}
	?>
</p>
<p>
	<?php
	switch ( $license['status'] ) {
		case 'active':
		case 'inactive':
		?>
			<a class="button button-small button-primary"
			href="<?php echo trailingslashit( set_url_scheme( SECUPRESS_WEB_MAIN, 'https' ) ) . _x( 'account', 'link to website (Only FR or EN!)', 'secupress' ); ?>"
			target="_blank"
			title="<?php _e( 'on secupress.me', 'secupress' ); ?>">
				<?php _e( 'Open My Account', 'secupress' ); ?>
				<span class="dashicons dashicons-admin-users"></span>
			</a>
		<?php
		break;
		case 'expired':
		?>
			<a class="button button-small button-primary"
			href="<?php echo trailingslashit( set_url_scheme( SECUPRESS_WEB_MAIN, 'https' ) ) . _x( 'checkout', 'link to website (Only FR or EN!)', 'secupress' ) . '/?edd_license_key=' . secupress_get_option( 'consumer_key' ) . '&download_id=14'; ?>"
			target="_blank"
			title="<?php _e( 'on secupress.me', 'secupress' ); ?>">
				<?php _e( 'Renew My License', 'secupress' ); ?>
				<span class="dashicons dashicons-star-filled"></span>
			</a>
		<?php
		break;
		default:
		?>
			<a class="button button-small button-primary"
			href="<?php echo trailingslashit( set_url_scheme( SECUPRESS_WEB_MAIN, 'https' ) ) . _x( 'pricing', 'link to website (Only FR or EN!)', 'secupress' ); ?>"
			target="_blank"
			title="<?php _e( 'on secupress.me', 'secupress' ); ?>">
				<?php _e( 'Get Pro Version', 'secupress' ); ?>
				<span class="dashicons dashicons-star-filled"></span>
			</a>
		<?php
	}
	?>
</p>
<?php
$value = ob_get_contents();
ob_end_clean();
$this->add_field( array(
	'title'        => __( 'My Account', 'secupress' ),
	'label_for'    => 'license_information',
	'type'         => 'html',
	'value'        => $value,
	'helpers'      => array(
		array(
			'type'        => $helper,
			'description' => $need_more,
		),
	),
) );