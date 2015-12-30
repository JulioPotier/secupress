<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'content_protect' );
$this->add_section( __( 'Content Protection', 'secupress' ) );


$field_name = $this->get_field_name( 'hotlink' );

$this->add_field(
	__( 'Anti-Hot-link', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'A hot-link is when someone embed your medias directly from your website, stealing your bandwidth.', 'secupress' ),
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'value'        => (int) secupress_is_submodule_active( 'sensitive-data', 'hotlink' ),
			'label'        => __( 'Yes, protect my medias from being hotlinked', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, protect my medias from being hotlinked', 'secupress' ),
		),
	)
);


$field_name = $this->get_field_name( 'blackhole' );

$this->add_field(
	__( 'Blackhole', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => sprintf( __( 'A blackhole is a forbidden folder, mentioned in the %1$s file as %2$s. If a bot do not respect this rule, its IP address will be banned.', 'secupress' ), '<code>robots.txt</code>', '<em>Disallowed</em>' ),
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'value'        => (int) secupress_is_submodule_active( 'sensitive-data', 'blackhole' ),
			'label'        => sprintf( __( 'Yes, add a blackhole in my %s file.', 'secupress' ), '<code>robots.txt</code>' ),
			'label_for'    => $field_name,
			'label_screen' => sprintf( __( 'Yes, add a blackhole in my %s file.', 'secupress' ), '<code>robots.txt</code>' ),
		),
	)
);
