<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

// Add the form manually.
add_action( 'secupress.settings.before_section_secupress_advanced_settings', array( $this, 'print_open_form_tag' ) );
add_action( 'secupress.settings.after_section_secupress_advanced_settings', array( $this, 'print_close_form_tag' ) );

$this->set_current_section( 'secupress_advanced_settings' );
$this->add_section( __( 'Advanced Settings', 'secupress' ) );

$disabled = false === secupress_show_adminbar( true );
$this->add_field( array(
	'title'             => __( 'Admin Bar Menu', 'secupress' ),
	'label_for'         => $this->get_field_name( 'admin-bar' ),
	'type'              => 'checkbox',
	'disabled'          => $disabled,
	'value'             => $disabled ? false : secupress_show_adminbar(),
	'label'             => sprintf( __( 'Yes, show the %s admin bar menu for me', 'secupress' ), SECUPRESS_PLUGIN_NAME ),
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => $disabled ? sprintf( __( 'The constant %s is set on %s.<br>Impossible to modify this setting from here.', 'secupress' ), secupress_code_me( 'SECUPRESS_MODE' ), secupress_code_me( 'adminbar' ) ) : '',
		),
	),
) );

$disabled = false === secupress_show_contextual_help( true );
$this->add_field( array(
	'title'             => __( 'Show Contextual Help & Tips', 'secupress' ),
	'label_for'         => $this->get_field_name( 'expert-mode' ),
	'type'              => 'checkbox',
	'disabled'          => $disabled,
	'value'             => $disabled ? false : secupress_show_contextual_help(),
	'label'             => sprintf( __( 'Yes, show contextual help in %s for me', 'secupress' ), SECUPRESS_PLUGIN_NAME ),
	'helpers'           => array(
		array(
			'type'        => 'force-description',
			'description' => $disabled ? sprintf( __( 'The constant %s is set on %s.<br>Impossible to modify this setting from here.', 'secupress' ), secupress_code_me( 'SECUPRESS_MODE' ), secupress_code_me( 'help' ) ) : '',
		),
	),
) );

$disabled = false === secupress_show_grade_system( true );
$this->add_field( array(
	'title'             => __( 'Grade System', 'secupress' ),
	'label_for'         => $this->get_field_name( 'grade-system' ),
	'type'              => 'checkbox',
	'disabled'          => $disabled,
	'value'             => $disabled ? false : secupress_show_grade_system(),
	'label'             => __( 'Yes, show the Grade system', 'secupress' ),
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => $disabled ? sprintf( __( 'The constant %s is set on %s.<br>Impossible to modify this setting from here.', 'secupress' ), secupress_code_me( 'SECUPRESS_MODE' ), secupress_code_me( 'grade' ) ) : '',
		),
	),
) );

$disabled       = true === secupress_is_expert_mode( true );
$expert_modules = secupress_get_expert_modules_on();
$this->add_field( array(
	'title'             => __( 'Expert Mode', 'secupress' ),
	'label_for'         => $this->get_field_name( 'expert-mode-main' ),
	'disabled'          => ! empty( $expert_modules ) || $disabled,
	'type'              => 'checkbox',
	'value'             => $disabled ? true : secupress_is_expert_mode(),
	'label'             => __( 'Yes, show <strong>experts features</strong>', 'secupress' ),
	'helpers'           => array(
		array(
			'type'        => 'help',
			'description' => sprintf( __( 'Search for this blue %s logo', 'secupress' ), SECUPRESS_PLUGIN_NAME ),
		),
		array(
			'type'        => 'force-warning',
			'description' => ! empty( $expert_modules ) ? __( 'Restricted Module Deactivation', 'secupress' ) . '<br>' . sprintf( _n( 'One Expert Module is still active. Deactivate it:', 'Some Expert Modules are still active. Deactivate them:', count( $expert_modules ), 'secupress' ) . ' <strong>' . wp_sprintf_l( '%l', $expert_modules ) . '</strong>' ) : '',
		),
		array(
			'type'        => 'description',
			'description' => $disabled ? sprintf( __( 'The constant %s is set on %s.<br>Impossible to modify this setting from here.', 'secupress' ), secupress_code_me( 'SECUPRESS_MODE' ), secupress_code_me( 'expert' ) ) : '',
		),
	),
) );
