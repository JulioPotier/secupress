<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'content_protect' );
$this->add_section( __( 'Content Protection', 'secupress' ) );


$this->add_field( array(
	'title'        => __( 'Anti-Hot-link', 'secupress' ),
	'description'  => __( 'A hot-link is when someone embed your medias directly from your website, stealing your bandwidth.', 'secupress' ),
	'label_for'    => $this->get_field_name( 'hotlink' ),
	'type'         => 'checkbox',
	'value'        => (int) secupress_is_submodule_active( 'sensitive-data', 'hotlink' ),
	'label'        => __( 'Yes, protect my medias from being hotlinked', 'secupress' ),
) );


$this->add_field( array(
	'title'        => __( 'Blackhole', 'secupress' ),
	'description'  => sprintf( __( 'A blackhole is a forbidden folder, mentioned in the %1$s file as %2$s. If a bot do not respect this rule, its IP address will be banned.', 'secupress' ), '<code>robots.txt</code>', '<em>Disallowed</em>' ),
	'label_for'    => $this->get_field_name( 'blackhole' ),
	'type'         => 'checkbox',
	'value'        => (int) secupress_is_submodule_active( 'sensitive-data', 'blackhole' ),
	'label'        => sprintf( __( 'Yes, add a blackhole in my %s file.', 'secupress' ), '<code>robots.txt</code>' ),
) );
