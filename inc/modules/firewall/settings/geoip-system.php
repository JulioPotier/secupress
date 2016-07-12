<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'geoip-system' );
$this->add_section( __( 'Country Management', 'secupress' ) );


$main_field_name = $this->get_field_name( 'type' );
$geoip_value     = '-1';

if ( secupress_is_submodule_active( 'firewall', 'geoip-system' ) ) {
	/**
	 * Make sure we have valid value if the submodule is active.
	 * The default value is 'blacklist'.
	 */
	$geoip_value = secupress_get_module_option( $main_field_name );
	$geoip_value = 'whitelist' === $geoip_value ? 'whitelist' : 'blacklist';
}

$this->add_field( array(
	'title'        => __( 'Use the GeoIP Management', 'secupress' ),
	'description'  => __( 'Country Management is an effective way to stop attacks of any types and stop malicious activities that originates from a specific region of the world.', 'secupress' ),
	'name'         => $main_field_name,
	'type'         => 'radios',
	'value'        => $geoip_value,
	'default'      => '-1',
	'label_screen' => __( 'Whitelist or Blacklist the countries', 'secupress' ),
	'options'      => array(
		'-1'        => __( 'I <strong>do not need</strong> to block or allow countries from visiting my website', 'secupress' ),
		'blacklist' => __( '<strong>Disallow</strong> the selected countries to visit my website (blacklist)', 'secupress' ),
		'whitelist' => __( '<strong>Only allow</strong> the selected countries to visit my website (whitelist)', 'secupress' ),
	),
	'helpers'      => array(
		array(
			'type'        => 'description',
			'description' => __( 'Remember that we detect a visit based on the IP address, so it\'s effective for about 99% of automated attacks.', 'secupress' ),
		),
	),
) );

$this->add_field( array(
	'title'        => __( 'Which countries?', 'secupress' ),
	'description'  => __( 'Add or remove countries you want to be manage from your website.', 'secupress' ),
	'depends'      => $main_field_name . '_blacklist ' . $main_field_name . '_whitelist',
	'type'         => 'countries',
	'name'         => $this->get_field_name( 'countries' ),
) );
