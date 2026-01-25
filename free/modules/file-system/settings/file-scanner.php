<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

$this->set_current_section( 'file-scanner' );
$this->set_section_description( '' );
$this->add_section( '', array( 'with_save_button' => false ) );


$this->add_field( array(
	// 'title'        => __( 'Files and Database Scanner', 'secupress' ),
	'name'         => $this->get_field_name( 'file-scanner' ),
	'type'         => 'file_scanner',
) );
