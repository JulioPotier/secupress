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
	$label  = __( 'Activate the license', 'secupress' );
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

$this->add_field( array(
	'title'        => __( 'E-mail Address', 'secupress' ),
	'label_for'    => 'consumer_email',
	'type'         => 'email',
	'attributes'   => $attributes,
	'value'        => defined( 'SECUPRESS_API_EMAIL' ) ? esc_attr( SECUPRESS_API_EMAIL ) : secupress_get_consumer_email(),
	'helpers'      => array(
		array(
			'type'        => 'help',
			'description' => _x( 'The one you used for your Pro account.', 'e-mail address', 'secupress' ),
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
			'description' => __( 'The license key obtained with your Pro account.', 'secupress' ),
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
			'description' => __( 'The license key obtained with your Pro account.', 'secupress' ),
		),
	),
) );

/*
$license   = secupress_get_option( 'license' );
$helper    = 'help';
$need_more = '';
if ( secupress_is_pro() && $license ) {
	if ( 0 === $license['limit'] ) { // Unlimited.
		$sites_number = sprintf( __( '%d / unlimited', 'secupress' ), (int) $license['count'] );
	} else {
		$need_more    = sprintf( __( 'Need more than %1$d sites?<br><a href="%2$s">Just ask for more!</a>', 'secupress' ), $license['limit'], SECUPRESS_WEB_MAIN . __( 'pricing', 'secupress' ) );
		$sites_number = sprintf( _n( '%1$d / %2$d site', '%1$d / %2$d sites', $license['count'], 'secupress' ), (int) $license['count'], (int) $license['limit'] );
	}
} else {
	$sites_number = _x( 'Free', 'feminine', 'secupress' );
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
			echo '<span class="dashicons dashicons-yes"></span>&nbsp;' . __( 'Active', 'secupress' );
		break;
		case 'expired':
			$need_more = __( 'Expired Licenses<br>don’t use the pro features!', 'secupress' );
			$helper    = 'warning';
			echo '<span class="dashicons dashicons-clock"></span>&nbsp;' . __( 'Expired', 'secupress' );
		break;
		case 'disabled':
			echo '<span class="dashicons dashicons-dismiss"></span>&nbsp;' . __( 'Disabled', 'secupress' );
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
			href="<?php echo SECUPRESS_WEB_MAIN . __( 'account', 'secupress' ); ?>"
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
			href="<?php echo SECUPRESS_WEB_MAIN . __( 'checkout', 'secupress' ) . '/?edd_license_key=' . secupress_get_option( 'consumer_key' ) . '&download_id=14'; ?>"
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
			href="<?php echo SECUPRESS_WEB_MAIN . __( 'pricing', 'secupress' ); ?>"
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
// $helper = 'help';
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

if ( ! secupress_is_white_label() ) {
	$free_message  = __( '<strong>Free Support</strong>: <a href="https://wordpress.org/support/plugin/secupress" lang="en">Community Forum</a>', 'secupress' );
	$free_message .= '<br>' . sprintf( __( '<strong>Priority Support</strong>: <a href="%ssupport#free">From 12$</a>', 'secupress' ), SECUPRESS_WEB_MAIN );
	$pro_message   = '<br>' . sprintf( __( '<strong>Priority Support</strong>: <a href="%ssupport">Available</a>', 'secupress' ), SECUPRESS_WEB_MAIN );

	$this->add_field( array(
		'title'        => __( 'Support', 'secupress' ),
		'label_for'    => 'support_info',
		'type'         => 'html',
		'value'        => secupress_is_pro() ? $pro_message : $free_message,
		'helpers'      => array(
			array(
				'type'        => 'help',
				'description' => ! secupress_is_pro() ? __( 'Priority and free support is not included in the free version since june 2018. You can still freely post a topic on the wp.org forums, or purchase a ticket on secupress.me.', 'secupress' ) : '',
			),
		),
	) );
}
*/
