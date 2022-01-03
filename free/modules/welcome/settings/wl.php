<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

// Add the form manually.
add_action( 'secupress.settings.before_section_secupress_display_white_label', array( $this, 'print_open_form_tag' ) );
add_action( 'secupress.settings.after_section_secupress_display_white_label', array( $this, 'print_close_form_tag' ) );

$this->set_current_section( 'secupress_display_white_label' );
$this->set_section_description( __( 'You can change the name of the plugin, this will be shown on the plugins page, only when activated. Leave the plugin name empty to remove the White Label.', 'secupress' ) );
$this->add_section( __( 'White Label', 'secupress' ) );

$this->add_field( array(
	'title'        => __( 'Plugin name', 'secupress' ),
	'label_for'    => $this->get_field_name( 'plugin_name' ),
	'type'         => 'text',
	'value'        => secupress_get_option( 'wl_plugin_name' ),
) );

$this->add_field( array(
	'title'        => __( 'Plugin URL', 'secupress' ),
	'label_for'    => $this->get_field_name( 'plugin_URI' ),
	'type'         => 'url',
	'value'        => secupress_get_option( 'wl_plugin_URI' ),
) );

$this->add_field( array(
	'title'        => __( 'Plugin author', 'secupress' ),
	'label_for'    => $this->get_field_name( 'author' ),
	'type'         => 'text',
	'value'        => secupress_get_option( 'wl_author' ),
) );

$this->add_field( array(
	'title'        => __( 'Plugin author URL', 'secupress' ),
	'label_for'    => $this->get_field_name( 'author_URI' ),
	'type'         => 'url',
	'value'        => secupress_get_option( 'wl_author_URI' ),
) );

$this->add_field( array(
	'title'        => __( 'Plugin description', 'secupress' ),
	'label_for'    => $this->get_field_name( 'description' ),
	'type'         => 'textarea',
	'value'        => secupress_get_option( 'wl_description' ),
) );
