<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


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
	'label_screen' => __( 'Allow or disallow countries', 'secupress' ),
	'options'      => array(
		'-1'        => __( '<strong>Do not block</strong> countries from visiting my website', 'secupress' ),
		'blacklist' => __( '<strong>Block</strong> the selected countries from visiting my website (disallowed list)', 'secupress' ),
		'whitelist' => __( '<strong>Only allow</strong> the selected countries to visit my website (allowed list)', 'secupress' ),
	),
	'helpers'      => array(
		array(
			'type'        => 'description',
			'description' => __( 'Remember that the detection of a visit is based on the IP address, so it’s effective for almost all automated attacks.', 'secupress' ),
		),
		array(
			'type'        => 'warning',
			'description' => __( 'This module will store GeoIP data in the database, raising it for about 25MB.', 'secupress' ),
		),
	),
) );

$this->add_field( array(
	'title'             => __( 'SEO bots GeoIP bypass', 'secupress' ),
	'description'       => __( 'SEO bots are allowed to visit your website even if they are coming from a blocked country.', 'secupress' ),
	'label_for'         => $main_field_name,
	'name'              => $this->get_field_name( 'seo-bypass' ),
	'type'              => 'checkbox',
	'depends'           => $main_field_name . '_blacklist ' . $main_field_name . '_whitelist',
	// 'value'             => secupress_get_module_option( 'geoip-system_seo-bypass' ) === 1,
	'label'             => __( 'Yes, still block SEO bots with GeoIP blocking', 'secupress' ),
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => __( 'If you block like the USA, any SEO bots will be blocked (Google?), keep this in mind.', 'secupress' ),
		),
		array(
			'type'        => 'warning',
			'description' => __( 'We recommand to let this setting deactivated.', 'secupress' ),
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

$lastupdate = secupress_get_option( 'geoips_last_update' );
$lastupdate = '1' === get_option( 'secupress_geoip_installed', 0 ) && $lastupdate ? $lastupdate : __( 'Not installed yet', 'secupress' );
$this->add_field( array(
	'title'        => __( 'Manual Update', 'secupress' ),
	'label_for'    => 'manual_update',
	'depends'      => '1' === get_option( 'secupress_geoip_installed', 0 ) ? $main_field_name . '_blacklist ' . $main_field_name . '_whitelist' : 'not_installed_yet',
	'type'         => 'html',
	'value'        => '1' === get_option( 'secupress_geoip_installed', 0 ) ? '<a href="' . wp_nonce_url( admin_url( 'admin-post.php?action=secupress_geoips_update_data' ), 'secupress_geoips_update_data' ) . '" class="button button-secondary">' . __( 'Update the GeoIP database now', 'secupress' ) . '</a>' : '<a disabled class="button button-secondary">' . __( 'Save changes first', 'secupress' ) . '</a>',
	'helpers'      => array(
		array(
			'type'        => 'help',
			'description' => sprintf( __( 'The GeoIP database will update everyday automatically.<br />If you encounter strange behaviour like too much blocking or not enough, try to update manually.<br>Last update: %s', 'secupress' ), $lastupdate ),
		),
	),
) );
