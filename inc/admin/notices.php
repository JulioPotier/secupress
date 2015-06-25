<?php
defined( 'ABSPATH' ) or	die( 'Cheatin\' uh?' );

/**
 * This warnings are displayed when the plugin can not be deactivated correctly
 *
 * @since 1.0
 */
add_action( 'admin_notices', 'secupress_bad_deactivations' );
function secupress_bad_deactivations()
{
	global $current_user;
	/** This filter is documented in inc/admin-bar.php */
	if ( current_user_can( apply_filters( 'secupress_capacity', 'administrator' ) ) && $msgs = get_transient( $current_user->ID . '_donotdeactivatesecupress' ) ) {

		delete_transient( $current_user->ID . '_donotdeactivatesecupress' );
		$errors = array();
		?>

		<div class="error">
			<?php
			foreach ( $msgs as $msg ) {

				switch( $msg ) {

					case 'htaccess' :
						$errors['htaccess'] = '<p>' . sprintf( __( '<b>%s</b> can not be deactivated because of <code>%s</code>.', 'rocket' ), SECUPRESS_PLUGIN_NAME, '.htaccess' ) . '<br>' . __( 'This file is not writable and we can not remove these directives.', 'rocket' ) . ' ' . sprintf( __( 'Maybe we do not have writing permissions for <code>%s</code>.', 'rocket' ), '.htaccess' ) . '<br>' . __( 'Please give us permissions or resolve the problem yourself. Then retry deactivation.', 'rocket' ) . '</p>';
						break;
				}

				/**
				  * Filter the output messages for each bad deactivation attempt.
				  *
				  * @since 2.0.0
				  *
				  * @param array $errors Contains the error messages to be filtered
				  * @param string $msg Contains the error type (wpconfig or htaccess)
				 */
				$errors = apply_filters( 'secupress_bad_deactivations', $errors, $msg );

			}

			// Display errors
			if ( count( $errors ) ) {
				array_map( 'printf', $errors );
			}

			/**
			  * Allow a "force deactivation" link to be printed, use at your own risks
			  *
			  * @since 2.0.0
			  *
			  * @param bool true will print the link
			 */
			$permit_force_deactivation = apply_filters( 'secupress_permit_force_deactivation', true );

			// We add a link to permit "force deactivation", use at your own risks.
			if ( $permit_force_deactivation ) {
				global $status, $page, $s;
				$plugin_file = SECUPRESS_PLUGIN_FILE;
				$secupress_nonce = wp_create_nonce( 'force_deactivation' );

				echo '<p><a href="'.wp_nonce_url('plugins.php?action=deactivate&amp;secupress_nonce=' . $secupress_nonce . '&amp;plugin=' . $plugin_file . '&amp;plugin_status=' . $status . '&amp;paged=' . $page . '&amp;s=' . $s, 'deactivate-plugin_' . $plugin_file).'">' . __( 'You can still force the deactivation by clicking here.', 'secupress' ) . '</a></p>';
			}
			?>
		</div>

	<?php
	}
}

/**
 * This warning is displayed when some plugins may conflict with WP Rocket
 *
 * @since 1.0
 */
add_action( 'admin_notices', 'secupress_plugins_to_deactivate' );
function secupress_plugins_to_deactivate()
{
	$plugins_to_deactivate = array();

	// Deactivate all plugins who can cause conflicts with WP Rocket
	$plugins = array(
		'wordfence/wordfence.php'
	);

	foreach ( $plugins as $plugin ) { //// array_filter
		if ( is_plugin_active( $plugin ) ) {
			$plugins_to_deactivate[] = $plugin;
		}
	}

	/** This filter is documented in inc/admin-bar.php */
	if ( current_user_can( apply_filters( 'secupress_capacity', 'administrator' ) )
		&& count( $plugins_to_deactivate )
	) { ?>

		<div class="error">
			<p><?php printf( __( '<b>%s</b>: The following plugins are not compatible with this plugin and may cause unexpected results:', 'rocket' ), SECUPRESS_PLUGIN_NAME ); ?></p>
			<ul class="rocket-plugins-error">
			<?php
			foreach ( $plugins_to_deactivate as $plugin ) {

				$plugin_data = get_plugin_data( WP_PLUGIN_DIR . DIRECTORY_SEPARATOR . $plugin);
				echo '<li>' . $plugin_data['Name'] . '</span> <a href="' . wp_nonce_url( admin_url( 'admin-post.php?action=deactivate_plugin&plugin=' . urlencode($plugin) ), 'deactivate_plugin' ) . '" class="button-secondary alignright">' . __( 'Deactivate', 'secupress' ) . '</a></li>';

			}
			?>
			</ul>
		</div>

	<?php
	}
}

/**
 * This warning is displayed when the wp-config.php file isn't writable
 *
 * @since 1.0
 */
add_action( 'admin_notices', 'secupress_warning_wp_config_permissions' );
function secupress_warning_wp_config_permissions()
{
	$config_file = secupress_find_wpconfig_path();

	if ( ! ( 'plugins.php' == $GLOBALS['pagenow'] && isset( $_GET['activate'] ) ) 
		/** This filter is documented in inc/admin-bar.php */
		&& current_user_can( apply_filters( 'secupress_capacity', 'administrator' ) )
		&& ! is_writable( $config_file ) ) {

		$boxes = get_user_meta( $GLOBALS['current_user']->ID, 'secupress_boxes', true );

		if ( ! in_array( __FUNCTION__, (array) $boxes ) ) { ?>

			<div class="error">
				<a href="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=secupress_ignore&box='.__FUNCTION__ ), 'secupress_ignore_'.__FUNCTION__ ); ?>" class="secupress-cross"><div class="dashicons dashicons-no"></div></a>
				<p>
				<?php
					printf( __( '<b>%s</b>: It seems we don\'t have <a href="%s" target="_blank">writing permissions</a> on <code>wp-config.php</code> file.', 'secupress'), SECUPRESS_PLUGIN_NAME, "http://codex.wordpress.org/Changing_File_Permissions" );
					echo '<br>';
					_e( 'To fix this you have to set writing permissions for <code>wp-config.php</code> and then save the settings again.', 'secupress' );
					echo '<br>';
					_e( 'If the message persists, you have to put the following code in your <code>wp-config.php</code> file so that it works correctly. Click on the field and press Ctrl-A to select all.', 'secupress' );
				?>
				</p>

				<?php
				// Get the content of the WP_CACHE constant added by WP Rocket
				// $define = "/** SecuPress */\r\ndefine( 'WP_CACHE', true );\r\n";
				?>

				<p><textarea readonly="readonly" id="rules" name="rules" class="large-text readonly" rows="2"><?php echo esc_textarea( $define ); ?></textarea></p>
			</div>

		<?php
		}

	}
}


/**
 * This warning is displayed when the .htaccess file doesn't exist or isn't writeable
 *
 * @since 1.0
 */
add_action( 'admin_notices', 'secupress_warning_htaccess_permissions' );
function secupress_warning_htaccess_permissions()
{
	$htaccess_file =  get_home_path() . '.htaccess';

	/** This filter is documented in inc/admin-bar.php */
	if ( current_user_can( apply_filters( 'secupress_capacity', 'administrator' ) )
	    && ( ! is_writable( $htaccess_file ) )
	    && $GLOBALS['is_apache'] ) { 

		$boxes = get_user_meta( $GLOBALS['current_user']->ID, 'secupress_boxes', true );

		if ( ! in_array( __FUNCTION__, (array) $boxes ) ) { ?>

			<div class="error">
				<a href="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=secupress_ignore&box='.__FUNCTION__ ), 'secupress_ignore_'.__FUNCTION__ ); ?>" class="secupress-cross"><div class="dashicons dashicons-no"></div></a>
				<p><b><?php echo SECUPRESS_PLUGIN_NAME; ?></b>: <?php printf( __( 'If you had <a href="%1$s" target="_blank">writing permissions</a> on <code>.htaccess</code> file, <b>%2$s</b> could do this automatically. This is not the case, so here are the rewrite rules you have to put in your <code>.htaccess</code> file for <b>%2$s</b> to work correctly. Click on the field and press Ctrl-A to select all.', 'rocket' ), 'http://codex.wordpress.org/Changing_File_Permissions', SECUPRESS_PLUGIN_NAME ) . '<br>' . __('<strong>Warning:</strong> This message will popup again and its content may be updated when saving the options', 'secupress'); ?></p>
				<p><textarea readonly="readonly" id="rules" name="rules" class="large-text readonly" rows="6"><?php echo esc_textarea( get_rocket_htaccess_marker() ); ?></textarea></p>
			</div>

		<?php
		}

	}
}


/**
 * This warnings are displayed when a module has been activated/deactivated
 *
 * @since 1.0
 */
add_action( 'admin_notices', 'secupress_warning_module_activity' );
function secupress_warning_module_activity()
{
	global $current_user;
	/** This filter is documented in inc/admin-bar.php */
	if ( current_user_can( apply_filters( 'secupress_capacity', 'administrator' ) ) ) {

		$activated_modules = get_site_transient( 'secupress_module_activation_' . $current_user->ID );
		$deactivated_modules = get_site_transient( 'secupress_module_deactivation_' . $current_user->ID );
		delete_site_transient( 'secupress_module_activation_' . $current_user->ID );
		delete_site_transient( 'secupress_module_deactivation_' . $current_user->ID );

		if ( $activated_modules && count( $activated_modules ) ) {
		?>
			<div class="updated">
				<p>
					<b><?php echo SECUPRESS_PLUGIN_NAME; ?></b>: 
					<?php echo sprintf( _n( 'This module have been activated: <ul><li>%s</li></ul>', 'These modules have been activated:<br><ul><li>%s</li></ul>', count( $activated_modules ), 'secupress' ), implode( '</li><li>', $activated_modules ) ); ?>
				</p>
			</div>
		<?php
		}

		if ( $deactivated_modules && count( $deactivated_modules ) ) {
		?>
			<div class="updated">
				<p>
					<b><?php echo SECUPRESS_PLUGIN_NAME; ?></b>: 
					<?php echo sprintf( _n( 'This module have been deactivated: <ul><li>%s</li></ul>', 'These modules have been deactivated:<br><ul><li>%s</li></ul>', count( $deactivated_modules ), 'secupress' ), implode( '</li><li>', $deactivated_modules ) ); ?>
				</p>
			</div>
		<?php
		}

	}
}

/**
 * This warnings are displayed when the backup email is not set
 *
 * @since 1.0
 */
add_action( 'admin_notices', 'secupress_warning_no_backup_email' );
function secupress_warning_no_backup_email()
{
	global $current_user;
	/** This filter is documented in inc/admin-bar.php */
	if ( ! get_user_meta( $current_user->ID, 'backup_email', true ) ) {
		?>
		<div class="error">
			<p>
				<b><?php echo SECUPRESS_PLUGIN_NAME; ?></b>: 
				<?php echo sprintf( __( 'Your <a href="%s#secupress_backup_email">Backup E-mail</a> isn\'t yet set. Please do it.', 'secupress' ), get_edit_profile_url() ); ?>
			</p>
		</div>
		<?php
	}
}

