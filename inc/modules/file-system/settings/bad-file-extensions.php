<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

global $is_apache, $is_nginx, $is_iis7;

// Open a form tag wrapping the following modules.
add_action( 'secupress.settings.before_section_bad-file-extensions', array( $this, 'print_open_form_tag' ) );
// Close the form tag wrapping these module.
add_action( 'secupress.settings.after_section_bad-file-extensions', array( $this, 'print_close_form_tag' ) );

$this->set_current_section( 'bad-file-extensions' );
$this->set_section_description( __( 'Many file extensions are known to be used by malware, or can pose a threat if they are vulnerable. Denying direct access to those files will prevent their use.', 'secupress' ) );
$this->add_section( __( 'Bad File Extensions', 'secupress' ) );

$main_field_name  = $this->get_field_name( 'activated' );
$is_plugin_active = (int) secupress_is_submodule_active( 'file-system', 'bad-file-extensions' );

$this->add_field( array(
	'title'             => __( 'Uploads folder', 'secupress' ),
	'name'              => $main_field_name,
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => $is_plugin_active,
	'label'             => __( 'Yes, deny direct access to those files in the uploads folder.', 'secupress' ),
) );


/**
 * If nginx or if `.htaccess`/`web.config` is not writable, display a textarea containing the rewrite rules for the Bad File Extensions.
 */
if ( $is_plugin_active && function_exists( 'secupress_bad_file_extensions_apache_rules' ) ) {
	$message = false;

	// Nginx.
	if ( $is_nginx ) {
		/** Translators: %s is a file name. */
		$message = sprintf( __( 'You need to add the following code to your %s file:', 'secupress' ), '<code>nginx.conf</code>' );
		$rules   = secupress_bad_file_extensions_nginx_rules();
	}
	// Apache.
	elseif ( $is_apache && ! secupress_root_file_is_writable( '.htaccess' ) ) {
		/** Translators: %s is a file name. */
		$message = sprintf( __( 'Your %s file is not writable, you need to add the following code to it:', 'secupress' ), '<code>.htaccess</code>' );
		$rules   = trim( secupress_bad_file_extensions_apache_rules() );
		$rules   = "# BEGIN SecuPress bad_file_extensions\n$rules\n# END SecuPress";
	}
	// IIS7.
	elseif ( $is_iis7 && ! secupress_root_file_is_writable( 'web.config' ) ) {
		/** Translators: %s is a file name. */
		$message = sprintf( __( 'Your %s file is not writable, you need to add the following code to it:', 'secupress' ), '<code>web.config</code>' );
		$rules   = secupress_bad_file_extensions_iis7_rules();
	}

	if ( $message ) {
		$this->add_field( array(
			'title'        => _x( 'Rules', 'rewrite rules', 'secupress' ),
			'description'  => $message,
			'depends'      => $main_field_name,
			'label_for'    => $this->get_field_name( 'bad_file_extensions_rules' ),
			'type'         => 'textarea',
			'value'        => $rules,
			'attributes'   => array(
				'readonly' => 'readonly',
				'rows'     => substr_count( $rules, "\n" ) + 1,
			),
		) );
	}
}
