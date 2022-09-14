<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


$this->set_current_section( 'uploads' );
$this->set_section_description( __( 'WordPress allows by default to add a plugin or theme by simply uploading a zip file. This is not secure since the file could contain any custom PHP code.<br/>By removing this possibility you ensure that plugins could only be added using FTP or via the official WordPress repository.', 'secupress' ) );
$this->add_section( __( 'Uploads Themes & Plugins', 'secupress' ) );


$field_name         = $this->get_field_name( 'activate' );

$is_plugin_active   = array();

$should_be_disabled = 'direct' !== get_filesystem_method() || false === secupress_get_ftp_fs_method();

if ( secupress_is_submodule_active( 'plugins-themes', 'uploads' ) ) {
	$is_plugin_active[] = 'uploads';
}

if ( ( $should_be_disabled && 'direct' !== get_filesystem_method() ) || secupress_is_submodule_active( 'plugins-themes', 'force-ftp' ) ) {
	$is_plugin_active[] = 'force-ftp';
}
$helpers = 	[
				[
					'depends'     => $field_name . '_uploads',
					'type'        => 'description',
					'description' => __( 'Themes and plugins can’t be added using .zip upload.', 'secupress' ),
				],
			];
if ( ! $should_be_disabled || secupress_is_submodule_active( 'plugins-themes', 'force-ftp' ) ) {
	$helpers[] = [
					'depends'     => $field_name . '_force-ftp',
					'type'        => 'description',
					'description' => __( 'Themes, plugins and translations can be uploaded but only with FTP credentials. It will be asked when needed.', 'secupress' ),
				];
} else {
	if ( 'direct' !== get_filesystem_method() ) {
		$helpers[] = [
						'type'        => 'warning',
						'description' => sprintf( __( 'You cannot use %s to restrict upload by FTP because it’s already set by another way.', 'secupress' ), SECUPRESS_PLUGIN_NAME ),
					];

	} else { // false === secupress_get_ftp_fs_method()
		$helpers[] = [
						'type'        => 'warning',
						'description' => __( 'You cannot restrict upload by FTP because you cannot use any FTP extension on this server (ssh2, ftpext, ftpsockets).', 'secupress' ),
					];

	}
}
$this->add_field( array(
	'title'             => sprintf( __( 'Disallow %s uploads', 'secupress' ), '<code>.zip</code>' ),
	'description'       => sprintf( __( 'Actual Upload Method: %s', 'secupress' ), '<em>' . secupress_verbose_ftp_fs_method( get_filesystem_method() ) . '</em>' ),
	'name'              => $field_name,
	'plugin_activation' => true,
	'disabled_values'   => ! $should_be_disabled || secupress_is_submodule_active( 'plugins-themes', 'force-ftp' ) ? [] : [ 'force-ftp' ],
	'type'              => 'radioboxes',
	'value'             => $is_plugin_active,
	'default'           => array(),
	'label_screen'      => sprintf( __( 'Disallow %s uploads', 'secupress' ), '<code>.zip</code>' ),
	'options'           => array(
		'uploads'       => __( 'Yes, <strong>disable</strong> any uploads of themes and plugins', 'secupress' ),
		'force-ftp'     => __( 'Yes, <strong>restrict</strong> all updates of themes, plugins, translations and WordPress Core by forcing FTP usage', 'secupress' ),
	),
	'helpers' => $helpers
) );
