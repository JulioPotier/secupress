<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

$this->set_current_section( 'file-scanner' );
$this->set_section_description( __( 'We scan your files, database and content to identify any non-WordPress elements and detect any modifications made to files or post content without your consent. We maintain a malware database that includes known web malwares, enabling us to identify and address any threats on your website.', 'secupress' ) );
$this->add_section( __( 'Malware Scanner', 'secupress' ), array( 'with_save_button' => false ) );


$this->add_field( array(
	// 'title'        => __( 'Files and Database Scanner', 'secupress' ),
	'name'         => $this->get_field_name( 'file-scanner' ),
	'type'         => 'file_scanner',
) );
