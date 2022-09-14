<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


$this->set_current_section( 'wp_config' );
$this->add_section( __( 'WordPress configuration file', 'secupress' ) );

$is_writable    = secupress_is_wpconfig_writable();
$mu_is_writable = wp_is_writable( WPMU_PLUGIN_DIR );
$mu_description = '';
if ( ! $mu_is_writable ) {
	$mu_description = sprintf( __( 'The <code>%s</code> dir is not writable, the constant cannot be changed.', 'secupress' ), esc_html( WPMU_PLUGIN_DIR ) );
}

$description = '';
if ( ! $is_writable ) {
	$description = sprintf( __( 'The <code>%s</code> file is not writable, the constants could not be changed.', 'secupress' ), secupress_get_wpconfig_filename() );
}


$active = (int) secupress_is_submodule_active( 'wordpress-core', 'wp-config-constant-debugging' );
$active = $active || ( defined( 'WP_DEBUG' ) && ! WP_DEBUG && defined( 'WP_DEBUG_DISPLAY' ) && ! WP_DEBUG_DISPLAY );
$this->add_field( array(
	'title'             => __( 'Debugging', 'secupress' ),
	'description'       => __( 'In a normal production environment you have to prevent errors from being displayed.', 'secupress' ),
	'label_for'         => $this->get_field_name( 'debugging' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => $active,
	'label'             => __( 'Yes, prevent my site to display errors.', 'secupress' ),
	'disabled'          => ! $is_writable,
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => ! $active ? secupress_get_wpconfig_constant_text( 'WP_DEBUG', 'FALSE' ) . '<br>' . secupress_get_wpconfig_constant_text( 'WP_DEBUG_DISPLAY', 'FALSE' ) : '',
		),
		array(
			'type'        => 'warning',
			'description' => $description,
		),
	),
) );


$active = (int) secupress_is_submodule_active( 'wordpress-core', 'wp-config-constant-locations' );
$active = $active || ( defined( 'RELOCATE' ) && ! RELOCATE && defined( 'WP_SITEURL' ) && get_site_url() === WP_SITEURL && defined( 'WP_HOME' ) && get_home_url() === WP_HOME );
$this->add_field( array(
	'title'             => __( 'Locations', 'secupress' ),
	'description'       => __( 'In a normal production environment you don’t need to relocate your site and home URL.', 'secupress' ),
	'label_for'         => $this->get_field_name( 'locations' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => $active,
	'label'             => __( 'Yes, prevent my site and home URL to be relocated.', 'secupress' ),
	'disabled'          => ! $is_writable,
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => ! $active ? secupress_get_wpconfig_constant_text( 'RELOCATE', 'FALSE' ) . '<br>' . secupress_get_wpconfig_constant_text( 'WP_SITEURL', get_site_url() ) . '<br>' . secupress_get_wpconfig_constant_text( 'WP_HOME', get_home_url() ) : '',
		),
		array(
			'type'        => 'warning',
			'description' => $description,
		),
	),
) );


$active = (int) secupress_is_submodule_active( 'wordpress-core', 'wp-config-constant-file-edit' );
$active = $active || ( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT );
$this->add_field( array(
	'title'             => __( 'File editing', 'secupress' ),
	'description'       => __( 'Administrators shouldn’t be able to edit the plugin and theme files directly within the WordPress administration area.', 'secupress' ),
	'label_for'         => $this->get_field_name( 'disallow_file_edit' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => $active,
	'label'             => __( 'Yes, disable the file editor', 'secupress' ),
	'disabled'          => ! $is_writable,
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => ! $active ? secupress_get_wpconfig_constant_text( 'DISALLOW_FILE_EDIT', 'TRUE' ) : '',
		),
		array(
			'type'        => 'warning',
			'description' => $description,
		),
	),
) );


$active = (int) secupress_is_submodule_active( 'wordpress-core', 'wp-config-constant-unfiltered-uploads' );
$active = $active || ( defined( 'ALLOW_UNFILTERED_UPLOADS' ) && ! ALLOW_UNFILTERED_UPLOADS );
$this->add_field( array(
	'title'             => __( 'Unfiltered uploads', 'secupress' ),
	'description'       => __( 'Administrators shouldn’t be allowed to upload any type of file.', 'secupress' ),
	'label_for'         => $this->get_field_name( 'disallow_unfiltered_uploads' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => $active,
	'label'             => __( 'Yes, filter uploads', 'secupress' ),
	'disabled'          => ! $is_writable,
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => ! $active ? secupress_get_wpconfig_constant_text( 'ALLOW_UNFILTERED_UPLOADS', 'FALSE' ) : '',
		),
		array(
			'type'        => 'warning',
			'description' => $description,
		),
	),
) );


$active = (int) secupress_is_submodule_active( 'wordpress-core', 'wp-config-constant-dieondberror' );
$active = $active || ( defined( 'DIEONDBERROR' ) && ! DIEONDBERROR );
$this->add_field( array(
	'title'             => __( 'Database Errors', 'secupress' ),
	'description'       => __( 'Database errors shouldn’t be displayed on front-office to prevent attackers to read your database prefix and tables.', 'secupress' ),
	'label_for'         => $this->get_field_name( 'dieondberror' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => $active,
	'label'             => __( 'Yes, hide any database error on front-office.', 'secupress' ),
	'disabled'          => ! $is_writable,
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => ! $active ? secupress_get_wpconfig_constant_text( 'DIEONDBERROR', 'FALSE' ) : '',
		),
		array(
			'type'        => 'warning',
			'description' => $description,
		),
	),
) );


$active = (int) secupress_is_submodule_active( 'wordpress-core', 'wp-config-constant-repair' );
$active = $active || ( defined( 'WP_ALLOW_REPAIR' ) && ! WP_ALLOW_REPAIR );
$this->add_field( array(
	'title'             => __( 'Repairing Database', 'secupress' ),
	'description'       => __( 'In a normal production environment your repair page shouldn’t be available.', 'secupress' ),
	'label_for'         => $this->get_field_name( 'repair' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => $active,
	'label'             => sprintf( __( 'Yes, force my <a href="%s" target="_blank">Database Repair Page</a> to be unavailable.', 'secupress' ), admin_url( 'maint/repair.php' ) ),
	'disabled'          => ! $is_writable,
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => ! $active ? secupress_get_wpconfig_constant_text( 'WP_ALLOW_REPAIR', 'FALSE' ) : '',
		),
		array(
			'type'        => 'warning',
			'description' => $description,
		),
	),
) );

$active = (int) secupress_is_submodule_active( 'wordpress-core', 'wp-config-constant-saltkeys' );
					// retrocompat < SP 2.0
$active   = $active || ( defined( 'SECUPRESS_SALT_KEYS_ACTIVE' ) && SECUPRESS_SALT_KEYS_ACTIVE ) || ( defined( 'SECUPRESS_SALT_KEYS_MODULE_ACTIVE' ) && SECUPRESS_SALT_KEYS_MODULE_ACTIVE );
$this->add_field( array(
	'title'             => __( 'WordPress Security Keys', 'secupress' ),
	'description'       => __( 'Creates tamper-proof security keys for your installation.', 'secupress' ),
	'label_for'         => $this->get_field_name( 'saltkeys' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => $active,
	'label'             => __( 'Yes, create secure keys for my installation.', 'secupress' ),
	'disabled'          => ! $is_writable,
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => ! $active ? __( '<strong>8 constants</strong> will be created in a must-use plugin and the ones in your <code>wp-config.php</code> file and database removed.', 'secupress' ) : '',
		),
		array(
			'type'        => 'warning',
			'description' => $active ? __( 'By deactivating this module you may need to sign back in.', 'secupress' ) : '',
		),
		array(
			'type'        => 'warning',
			'description' => $description,
		),
	),
) );

if ( $active ) {
	$this->add_field( array(
		'title'       => __( 'Regenerate the secure keys', 'secupress' ),
		'type'        => 'html',
		'description' => '<a href="' . wp_nonce_url( admin_url( 'admin-post.php?action=secupress-regen-keys' ), 'secupress-regen-keys' ) . '"' . ' id="secupress-regen-keys" class="button secupress-button button-small">' . __( 'Regenerate the secure keys', 'secupress' ) . '</a>'
	) );
}

$active = (int) secupress_is_submodule_active( 'wordpress-core', 'wp-config-constant-cookiehash' );
$active = $active || ( defined( 'COOKIEHASH' ) && md5( get_site_option( 'siteurl' ) ) !== COOKIEHASH );
$this->add_field( array(
	'title'             => __( 'WordPress Cookie Default Name', 'secupress' ),
	'description'       => __( 'Every WordPress cookie contains a string, but we can guess it for any site. Don’t reveal yours, it will be harder to target for some hacks.', 'secupress' ),
	'label_for'         => $this->get_field_name( 'cookiehash' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => $active,
	'label'             => __( 'Yes, change my WP cookie default value for something random.', 'secupress' ),
	'disabled'          => ! $mu_is_writable,
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => ! $active ? secupress_get_wpconfig_constant_text( 'COOKIEHASH', __( '[a random string]', 'secupress' ) ) : '',
		),
		array(
			'type'        => 'warning',
			'description' => $active ? __( 'By deactivating this module you may need to sign back in.', 'secupress' ) : '',
		),
		array(
			'type'        => 'warning',
			'description' => $mu_description,
		),
	),
) );


if ( ! $is_writable ) {
	$this->add_field( array(
		'type'  => 'html',
		/** Translators: 1 is a file name, 2 is a code. */
		'value' => sprintf( __( 'These options are disabled because the %1$s file is not writable. Please apply %2$s write rights to the file. <a href="https://docs.secupress.me/article/152-apply-write-rights-to-files">Need help?</a>', 'secupress' ), '<code>' . secupress_get_wpconfig_filename() . '</code>', '<code>0644</code>' ),
	) );
}
