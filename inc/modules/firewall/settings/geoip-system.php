<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'geoip-system' );
$this->add_section( __( 'Country Management', 'secupress' ) );


$main_field_name = $this->get_field_name( 'type' );
$geoip_value     = '-1';

if ( secupress_is_pro() && secupress_is_submodule_active( 'firewall', 'geoip-system' ) ) {
	/**
	 * Make sure we have valid value if the submodule is active.
	 * The default value is 'blacklist'.
	 */
	$geoip_value = secupress_get_module_option( $main_field_name );
	$geoip_value = 'whitelist' === $geoip_value ? 'whitelist' : 'blacklist';
}

$this->add_field( array(
	'title'        => __( 'Use GeoIP Management', 'secupress' ),
	'description'  => __( 'Country management is an effective way to stop attacks of any type and stop malicious activities that originate from a specific region of the world.', 'secupress' ),
	'name'         => $main_field_name,
	'type'         => 'radios',
	'value'        => $geoip_value,
	'default'      => '-1',
	'label_screen' => __( 'Whitelist or blacklist the countries', 'secupress' ),
	'options'      => array(
		'-1'        => __( '<strong>Do not block</strong> countries from visiting my website', 'secupress' ),
		'blacklist' => __( '<strong>Block</strong> the selected countries from visiting my website (blacklist)', 'secupress' ),
		'whitelist' => __( '<strong>Only allow</strong> the selected countries to visit my website (whitelist)', 'secupress' ),
	),
	'helpers'      => array(
		array(
			'type'        => 'description',
			'description' => __( 'Remember that the detection of a visit is based on the IP address, so it\'s effective for almost all automated attacks.', 'secupress' ),
		),
	),
) );

$this->add_field( array(
	'title'        => __( 'Which countries?', 'secupress' ),
	'description'  => __( 'Add or remove countries you want to manage for your website.', 'secupress' ),
	'depends'      => $main_field_name . '_blacklist ' . $main_field_name . '_whitelist',
	'type'         => 'countries',
	'name'         => $this->get_field_name( 'countries' ),
) );
