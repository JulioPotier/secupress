<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'content_protect' );
$this->add_section( __( 'Content Protection', 'secupress' ) );


$field_name = $this->get_field_name( 'hotlink' );
$this->add_field(
	__( 'Anti-Hotlink', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'A hotlink is when someone embed your medias directly from your website, stealing your bandwith.', 'secupress' ) . ( secupress_is_pro() ? '' : secupress_get_pro_version_string( '<br>%s') ),
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'label'        => __( 'Yes, protect my medias from being hotlinked', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, protect my medias from being hotlinked', 'secupress' ),
			'readonly'     => ! secupress_is_pro(),
		),
	)
);

$field_name = $this->get_field_name( 'blackhole' );
$this->add_field(
	__( 'Blackhole', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => sprintf( __( 'A blackhole is a forbidden folder, mentionned in the %1$s file as %2$s. If a bot do not respect this rule, its IP address will be banned.', 'secupress' ), '<code>robots.txt</code>', '<em>Disallowed</em>' ),
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'label'        => sprintf( __( 'Yes, add a blackhole in my %s file.', 'secupress' ), '<code>robots.txt</code>' ),
			'label_for'    => $field_name,
			'label_screen' => sprintf( __( 'Yes, add a blackhole in my %s file.', 'secupress' ), '<code>robots.txt</code>' ),
		),
	)
);
