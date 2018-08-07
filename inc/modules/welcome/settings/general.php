<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );

// // Add the form manually.
add_action( 'secupress.settings.before_section_general', array( $this, 'print_open_form_tag' ) );
add_action( 'secupress.settings.after_section_general', array( $this, 'print_close_form_tag' ) );

$this->set_current_section( 'general' );
$this->add_section( __( 'General Settings', 'secupress' ) );


$this->add_field( [
	'title'             => __( 'Expert Mode', 'secupress' ),
	'description'       => __( 'Expert Mode will hide the descriptions and helpers in all the module pages. Less text, more clear.', 'secupress' ),
	'name'              => $this->get_field_name( 'expert-mode' ),
	'type'              => 'checkbox',
	'label_for'         => $this->get_field_name( 'expert-mode' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'users-login', 'expert-mode' ),
	'label'             => __( 'Yes, remove helpers and descriptions.', 'secupress' ),
] );
