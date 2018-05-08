<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'wp_config' );
$this->add_section( __( 'WordPress configuration file', 'secupress' ) );

$is_writable = secupress_is_wpconfig_writable();

$description = null;
if ( ! $is_writable ) {
	$description = __( 'The <code>wp-config.php</code> file is not writable, the constants could not be changed.', 'secupress' );
}

$active = (int) secupress_is_submodule_active( 'wordpress-core', 'wp-config-constant-file-edit' );

$this->add_field( array(
	'title'             => __( 'File edition', 'secupress' ),
	'description'       => sprintf( __( 'By default Administrators are able to edit the plugins and themes\' files directly within the WordPress administration area. It is insecure and should be disabled. By activating this option, you will set the constant %s and disable the plugins and themes editor.', 'secupress' ), '<code>DISALLOW_FILE_EDIT</code>' ),
	'label_for'         => $this->get_field_name( 'disallow_file_edit' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => $active,
	'label'             => __( 'Yes, disable the file editor', 'secupress' ),
	'disabled'          => ! $is_writable,
	'helpers'           => array(
		array(
			'type'        => 'warning',
			'description' => $description,
		),
	),
) );


$active = (int) secupress_is_submodule_active( 'wordpress-core', 'wp-config-constant-unfiltered-uploads' );

$this->add_field( array(
	'title'             => __( 'Unfiltered uploads', 'secupress' ),
	'description'       => sprintf( __( 'A constant (%s) may be defined to allow Administrators to upload any type of file. Of course it is insecure and shouldn\'t be done. By activating this option, you will remove this constant and allow only files with common type to be uploaded.', 'secupress' ), '<code>ALLOW_UNFILTERED_UPLOADS</code>' ),
	'label_for'         => $this->get_field_name( 'disallow_unfiltered_uploads' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => $active,
	'label'             => __( 'Yes, filter uploads', 'secupress' ),
	'disabled'          => ! $is_writable,
	'helpers'           => array(
		array(
			'type'        => 'warning',
			'description' => $description,
		),
	),
) );


if ( ! $is_writable ) {
	$this->add_field( array(
		'type'  => 'html',
		/** Translators: 1 is a file name, 2 is a code. */
		'value' => sprintf( __( 'These options are disabled because the %1$s file is not writable. Please apply %2$s write rights to the file. <a href="https://docs.secupress.me/article/152-apply-write-rights-to-files">Need help?</a>', 'secupress' ), '<code>wp-config.php</code>', '<code>0644</code>' ),
	) );
}
