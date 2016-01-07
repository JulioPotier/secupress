<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

$this->set_current_section( 'file-scanner' );
$this->add_section( __( 'Files Scanner', 'secupress' ), array( 'with_save_button' => false ) );


$this->add_field( array(
	'title'        => __( 'File modification Scan', 'secupress' ),
	'description'  => __( 'Scanning your file will reveal which files are not from WordPress and which files have been modified from the core. Then a history will be compared at each next scan to show you the differences', 'secupress' ),
	'name'         => $this->get_field_name( 'file-scanner' ),
	'type'         => 'file_scanner',
) );


$this->add_field( array(
	'title'        => __( 'Malware Scan', 'secupress' ),
	'description'  => __( 'Some Web malwares are know over the web, we daily add them to our database and use it to detect that on your website', 'secupress' ),
	'name'         => $this->get_field_name( 'virus-scanner' ),
	'type'         => 'virus_scanner',
) );
