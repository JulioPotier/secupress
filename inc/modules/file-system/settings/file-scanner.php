<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

$this->set_current_section( 'file-scanner' );
$this->add_section( __( 'Files Scanner', 'secupress' ) );


$field_name = $this->get_field_name( 'file-scanner' );

$this->add_field(
	__( 'File modification Scan', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'Scanning your file will reveal which files are not from WordPress and which files have been modified from the core. Then a history will be compared at each next scan to show you the differences', 'secupress' ),
	),
	array(
		array(
			'type'         => 'file_scanner',
		),
	)
);

$field_name = $this->get_field_name( 'virus-scanner' );

$this->add_field(
	__( 'Malware Scan', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'Some Web malwares are know over the web, we daily add them to our database and use it to detect that on your website', 'secupress' ) .
		( secupress_is_pro() ? '' : secupress_get_pro_version_string( '<br>%s') ),
		// 'readonly'     => ! secupress_is_pro(), // done in virus_scanner
	),
	array(
		array(
			'type'         => 'virus_scanner',
		),
	)
);
