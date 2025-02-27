<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


$this->set_current_section( 'uploads' );
$this->set_section_description( __( 'WordPress allows uploading plugins or themes via zip files, which can pose security risks with custom PHP code.<br/>Disabling this ensures plugins can only be added via FTP or the official WordPress repository.', 'secupress' ) );
$this->add_section( __( 'Themes & Plugins Installation', 'secupress' ) );


$this->add_field( array(
	'title'             => __( 'Reinstall all your plugins', 'secupress' ),
	'description'       => __( 'This will reinstall a fresh and up to date version of every plugin from the official repository.', 'secupress' ),
	'type'              => 'html',
	'value'             => get_submit_button( __( 'Reinstall all plugins', 'secupress' ), 'secupress-button-small button button-small secupress-button', 'reinstall-plugins', true, ['data-nonce' => wp_create_nonce( 'secupress_reinstall_plugins' )] ) .
							'<ul class="secupress-show-list" id="reinstall-plugins-results"></ul>',
) );

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
					'description' => __( 'Themes and plugins cannot be added using .zip upload.', 'secupress' ),
				],
			];
if ( ! $should_be_disabled || secupress_is_submodule_active( 'plugins-themes', 'force-ftp' ) ) {
	$helpers[] = [
					'depends'     => $field_name . '_force-ftp',
					'type'        => 'description',
					'description' => __( 'Themes, plugins, and translations can be uploaded, but only with FTP credentials. You will be prompted when needed.', 'secupress' ),
				];
} else {
	if ( 'direct' !== get_filesystem_method() ) {
		$helpers[] = [
						'type'        => 'warning',
						'description' => sprintf( __( 'You can‘t use %s to restrict FTP uploads; it‘s already set up differently.', 'secupress' ), SECUPRESS_PLUGIN_NAME ),
					];

	} else { // false === secupress_get_ftp_fs_method()
		$helpers[] = [
						'type'        => 'warning',
						'description' => __( 'You cannot restrict FTP uploads because there are no FTP extensions available on this server (ssh2, ftpext, ftpsockets).', 'secupress' ),
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
