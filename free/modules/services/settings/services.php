<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

$this->add_section( __( 'Our Professional Services', 'secupress' ), array( 'with_save_button' => false ) );

$this->add_field( array(
	'title'        => __( 'Professional Configuration', 'secupress' ),
	'description'  => __( 'We will handle the configuration of the plugin for you<br>for a fee of $120', 'secupress' ),
	'name'         => $this->get_field_name( 'proconfig' ),
	'disabled'     => true,
	'type'         => 'field_button',
	'style'        => 'primary',
	'label'        => __( 'Request a Professional Configuration', 'secupress' ),
	'url'          => trailingslashit( set_url_scheme( SECUPRESS_WEB_MAIN, 'https' ) ) . _x( 'checkout/?currency=USD', 'link to website (Only FR or EN!)', 'secupress' ) . '&edd_action=add_to_cart&download_id=4077',
) );

$this->add_field( array(
	'title'        => __( 'Malware removal', 'secupress' ),
	'description'  => __( 'We will clean up your website from any security issues<br>for a fee of $360', 'secupress' ),
	'name'         => $this->get_field_name( 'got-hacked' ),
	'disabled'     => true,
	'type'         => 'field_button',
	'style'        => 'primary',
	'label'        => __( 'Request a Website cleansing', 'secupress' ),
	'url'          => trailingslashit( set_url_scheme( SECUPRESS_WEB_MAIN, 'https' ) ) . _x( 'checkout/?currency=USD', 'link to website (Only FR or EN!)', 'secupress' ) . '&edd_action=add_to_cart&download_id=4811',
) );

$this->add_field( array(
	'title'        => __( 'Security Monitoring', 'secupress' ),
	'description'  => __( 'Remove the hassle of checking security yourself with our Website Security Monitoring Services.<br>We have plan starting at $39', 'secupress' ),
	'name'         => $this->get_field_name( 'monitoring' ),
	'disabled'     => true,
	'type'         => 'field_button',
	'style'        => 'primary',
	'label'        => __( 'Visit our page for comparing plans', 'secupress' ),
	'url'          => trailingslashit( set_url_scheme( SECUPRESS_WEB_MAIN, 'https' ) ) . _x( 'monitoring/?currency=USD', 'link to website (Only FR or EN!)','secupress' ),
) );

if ( secupress_has_pro() ) {
	$this->add_field( array(
		'title'        => __( 'More Websites!', 'secupress' ),
		'description'  => __( 'Need more websites on your license?<br>Ensure all your websites are secure.', 'secupress' ),
		'name'         => $this->get_field_name( 'more-websites' ),
		'disabled'     => true,
		'type'         => 'field_button',
		'style'        => 'primary',
		'label'        => __( 'Upgrade your current license plan', 'secupress' ),
		'url'          => trailingslashit( set_url_scheme( SECUPRESS_WEB_MAIN, 'https' ) ) . _x( 'account', 'link to website (Only FR or EN!)','secupress' ),
	) );
}