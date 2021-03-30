<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

$this->set_current_section( 'file-scanner' );
$this->set_section_description( __( 'Scanning your files and database will reveal which ones are not from WordPress and which files or post content have been modified without your consent. Some web malwares are known around the web, we add them to our malware database and use it to detect what’s on your website.', 'secupress' ) );
$this->add_section( __( 'Malware Scanner', 'secupress' ), array( 'with_save_button' => false ) );


$this->add_field( array(
	'title'        => __( 'Files and Database Scanner', 'secupress' ),
	'name'         => $this->get_field_name( 'file-scanner' ),
	'type'         => 'file_scanner',
) );
