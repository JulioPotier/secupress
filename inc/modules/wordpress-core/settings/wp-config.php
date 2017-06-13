<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'wp_config' );
$this->add_section( __( 'WordPress configuration file', 'secupress' ) );


$is_writable = secupress_is_wpconfig_writable();

$active     = (int) secupress_is_submodule_active( 'wordpress-core', 'wp-config-constant-file-edit' );
$can_manage = $active || ! defined( 'DISALLOW_FILE_EDIT' ) || ! DISALLOW_FILE_EDIT;

$this->add_field( array(
	'title'             => __( 'File edition', 'secupress' ),
	'description'       => sprintf( __( 'By default Administrators are able to edit the plugins and themes\' files directly within the WordPress administration area. It is insecure and should be disabled. By activating this option, you will set the constant %s and disable the plugins and themes editor.', 'secupress' ), '<code>DISALLOW_FILE_EDIT</code>' ),
	'label_for'         => $this->get_field_name( 'disallow_file_edit' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => $active,
	'label'             => __( 'Yes, disable the file editor', 'secupress' ),
	'disabled'          => ! $can_manage || ! $is_writable,
	'helpers'           => array(
		array(
			'type'        => 'help',
			'description' => ! $can_manage ? __( 'Option unavailable, the protection is already set by another method than the plugin.', 'secupress' ) : null,
		),
	),
) );


$active     = (int) secupress_is_submodule_active( 'wordpress-core', 'wp-config-constant-unfiltered-html' );
$can_manage = $active || ! defined( 'DISALLOW_UNFILTERED_HTML' ) || ! DISALLOW_UNFILTERED_HTML;

$this->add_field( array(
	'title'             => __( 'Unfiltered HTML in post editor', 'secupress' ),
	'description'       => sprintf(
		/** Translators: 1 and 2 are HTML tags, 3 is a link to "shortcodes", 4 is a link to "embeds", 5 is a PHP constant name. */
		__( 'By default Administrators are allowed to write any type of <abbr title="Hypertext Markup Language">HTML</abbr> in the post editor, including unsafe HTML tags like %1$s and %2$s. This kind of tag is highly insecure and %3$s or %4$s must be used instead. By activating this option, you will set the constant %5$s and allow only common HTML tags to be used in the post editor.', 'secupress' ),
		'<code>&lt;script&gt;</code>',
		'<code>&lt;iframe&gt;</code>',
		'<a href="' . __( 'https://codex.wordpress.org/Shortcode', 'secupress' ) . '" target="_blank" title="' . esc_attr__( 'Open in a new window.', 'secupress' ) . '">' . __( 'shortcodes', 'secupress' ) . '</a>',
		'<a href="' . __( 'https://codex.wordpress.org/Embeds', 'secupress' ) . '" target="_blank" title="' . esc_attr__( 'Open in a new window.', 'secupress' ) . '">' . __( 'embeds', 'secupress' ) . '</a>',
		'<code>DISALLOW_UNFILTERED_HTML</code>'
	),
	'label_for'         => $this->get_field_name( 'disallow_unfiltered_html' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => $active,
	'label'             => __( 'Yes, filter HTML in post editor', 'secupress' ),
	'disabled'          => ! $can_manage || ! $is_writable,
	'helpers'           => array(
		array(
			'type'        => 'help',
			'description' => ! $can_manage ? __( 'Option unavailable, the protection is already set by another method than the plugin.', 'secupress' ) : null,
		),
		array(
			'type'        => 'warning',
			/** Translators: 1 and 2 are HTML tags. */
			'description' => $can_manage ? sprintf( __( 'by activating this option, %1$s and %2$s tags won\'t be allowed int the post editor anymore!', 'secupress' ), '<code>&lt;script&gt;</code>', '<code>&lt;iframe&gt;</code>' ) : null,
		),
	),
) );


$active      = (int) secupress_is_submodule_active( 'wordpress-core', 'wp-config-constant-unfiltered-uploads' );
$can_manage  = $active || defined( 'ALLOW_UNFILTERED_UPLOADS' ) && ALLOW_UNFILTERED_UPLOADS;
$description = null;

if ( ! $can_manage ) {
	$description = defined( 'ALLOW_UNFILTERED_UPLOADS' ) ? __( 'Option unavailable, the constant is already defined with the good value.', 'secupress' ) : __( 'Option unavailable, the constant is not defined.', 'secupress' );
}

$this->add_field( array(
	'title'             => __( 'Unfiltered uploads', 'secupress' ),
	'description'       => sprintf( __( 'A constant (%s) may be defined to allow Administrators to upload any type of file. Of course it is insecure and shouldn\'t be done. By activating this option, you will remove this constant and allow only files with common type to be uploaded.', 'secupress' ), '<code>ALLOW_UNFILTERED_UPLOADS</code>' ),
	'label_for'         => $this->get_field_name( 'disallow_unfiltered_uploads' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => $active,
	'label'             => __( 'Yes, filter uploads', 'secupress' ),
	'disabled'          => ! $can_manage || ! $is_writable,
	'helpers'           => array(
		array(
			'type'        => 'help',
			'description' => $description,
		),
	),
) );


if ( ! $is_writable ) {
	$this->add_field( array(
		'type'  => 'html',
		/** Translators: 1 is a file name, 2 is a code. */
		'value' => sprintf( __( 'These options are disabled because the %1$s file is not writable. Please apply %2$s write rights to the file.', 'secupress' ), '<code>wp-config.php</code>', '<code>0644</code>' ),
	) );
}
