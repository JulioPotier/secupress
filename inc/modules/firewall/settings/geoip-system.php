<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'geoip-system' );
$this->add_section( __( 'Country Managment', 'secupress' ) );


$field_name = $this->get_field_name( 'geoip-system' );
$main_field_name = $field_name;

$this->add_field(
	__( 'Use the GeoIP Managment', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'Country Managment is an effective way to stop attacks of any types and stop malicious activities that originates from a specific region of the world.', 'secupress' ),
	),
	array(
		array(
			'type'         => 'radios',
			'name'         => $field_name,
			'options'      => array( 
									'-1'        => __( 'I <strong>do not need</strong> to block or allow countries from visiting my website', 'secupress' ),
									'blacklist' => __( '<strong>Disallow</strong> the selected countries to visit my website (blacklist)', 'secupress' ), 
									'whitelist' => __( '<strong>Only allow</strong> the selected countries to visit my website (whitelist)', 'secupress' )
								),
			'default'      => '-1',
			'label_for'    => $field_name,
			'label_screen' => __( 'Whitelist or Blacklist the countries', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => $field_name,
			'description'  => __( 'Remember that we detect a visit based on the IP address, so it\'s effective for about 99% of automated attacks.', 'secupress' ),
		),
	)
);

$field_name = $this->get_field_name( 'geoip-countries' );
$GeoIP      = new GeoIP;
$countries = array(
	'AF' => array( 'Africa' ),
	'AN' => array( 'Antarctica' ),
	'AS' => array( 'Asia' ),
	'EU' => array( 'Europe' ),
	'OC' => array( 'Oceania' ),
	'NA' => array( 'North America' ),
	'SA' => array( 'South America' ),
);
foreach( $GeoIP->GEOIP_CONTINENT_CODES as $index => $code ) {
	$countries[ $code ][ $GeoIP->GEOIP_COUNTRY_CODES[ $index ] ] = $GeoIP->GEOIP_COUNTRY_NAMES [ $index ];
}
unset( $countries['--'] );
$this->add_field(
	__( 'Which countries?', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'Add or remove countries you want to be manage from your website.', 'secupress' ),
	),
	array(
		'depends_on'       => $main_field_name . '_blacklist' . ' ' . $main_field_name . '_whitelist',
		array(
			'type'         => 'countries',
			'name'         => $field_name,
			'options'      => $countries,
		),
		array(
			'type'         => 'helper_description',
			'name'         => $field_name,
		),
	)
);
unset( $countries );