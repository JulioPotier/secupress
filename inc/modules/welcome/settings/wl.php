<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );

// Add the form manually.
add_action( 'secupress.settings.before_section_secupress_display_white_label', array( $this, 'print_open_form_tag' ) );
add_action( 'secupress.settings.after_section_secupress_display_white_label', array( $this, 'print_close_form_tag' ) );

$this->set_current_section( 'secupress_display_white_label' );
$this->set_section_description( __( 'You can change the name of the plugin, this will be shown on the plugins page, only when activated.', 'secupress-pro' ) );
$this->add_section( __( 'White Label', 'secupress-pro' ) );

$this->add_field( array(
	'title'        => __( 'Plugin name', 'secupress-pro' ),
	'label_for'    => $this->get_field_name( 'plugin_name' ),
	'type'         => 'text',
	'value'        => secupress_get_option( 'wl_plugin_name' ),
) );

$this->add_field( array(
	'title'        => __( 'Plugin URL', 'secupress-pro' ),
	'label_for'    => $this->get_field_name( 'plugin_URI' ),
	'type'         => 'url',
	'value'        => secupress_get_option( 'wl_plugin_URI' ),
) );

$this->add_field( array(
	'title'        => __( 'Plugin author', 'secupress-pro' ),
	'label_for'    => $this->get_field_name( 'author' ),
	'type'         => 'text',
	'value'        => secupress_get_option( 'wl_author' ),
) );

$this->add_field( array(
	'title'        => __( 'Plugin author URL', 'secupress-pro' ),
	'label_for'    => $this->get_field_name( 'author_URI' ),
	'type'         => 'url',
	'value'        => secupress_get_option( 'wl_author-URI' ),
) );

$this->add_field( array(
	'title'        => __( 'Plugin description', 'secupress-pro' ),
	'label_for'    => $this->get_field_name( 'description' ),
	'type'         => 'textarea',
	'value'        => secupress_get_option( 'wl_description' ),
) );
