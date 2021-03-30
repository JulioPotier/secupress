<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

// Add the form manually.
add_action( 'secupress.settings.before_section_secupress_advanced_settings', array( $this, 'print_open_form_tag' ) );
add_action( 'secupress.settings.after_section_secupress_advanced_settings', array( $this, 'print_close_form_tag' ) );

$this->set_current_section( 'secupress_advanced_settings' );
$this->add_section( __( 'Advanced Settings', 'secupress' ) );

$this->add_field( array(
	'title'             => __( 'Admin Bar', 'secupress' ),
	'label_for'         => $this->get_field_name( 'admin-bar' ),
	'type'              => 'checkbox',
	'value'             => secupress_get_module_option( 'advanced-settings_admin-bar', true ),
	'label'             => sprintf( __( 'Yes, display the %s admin bar menu', 'secupress' ), SECUPRESS_PLUGIN_NAME ),
) );

$this->add_field( array(
	'title'             => __( 'Grade System', 'secupress' ),
	'label_for'         => $this->get_field_name( 'grade-system' ),
	'type'              => 'checkbox',
	'value'             => secupress_get_module_option( 'advanced-settings_grade-system', true ),
	'label'             => sprintf( __( 'Yes, use and display the Grade system in %s', 'secupress' ), SECUPRESS_PLUGIN_NAME ),
) );

$this->add_field( array(
	'title'             => __( 'Expert Mode', 'secupress' ),
	'label_for'         => $this->get_field_name( 'expert-mode' ),
	'type'              => 'checkbox',
	'value'             => secupress_get_module_option( 'advanced-settings_expert-mode', false ),
	'label'             => sprintf( __( 'Yes, hide all the contextual helps in %s', 'secupress' ), SECUPRESS_PLUGIN_NAME ),
) );
