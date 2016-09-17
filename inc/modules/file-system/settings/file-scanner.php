<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

$this->set_current_section( 'file-scanner' );
$this->set_section_description( __( 'Scanning your files will reveal which ones are not from WordPress and which files have been modified from the core. Some web malwares are known around the web, we add them daily to our database and use it to detect that on your website.', 'secupress' ) );
$this->add_section( __( 'Malware Scanner', 'secupress' ), array( 'with_save_button' => false ) );


$this->add_field( array(
	'title'        => __( 'Files Scanner', 'secupress' ),
	'name'         => $this->get_field_name( 'file-scanner' ),
	'type'         => 'file_scanner',
) );
