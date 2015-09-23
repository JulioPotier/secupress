<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Gives back the module title
 *
 * @since 1.0
 *
 * @param (string)$module : the desired module
*/
function secupress_get_module_title( $module = false ) { //// dans SecuPress_Settings
	$module = $module ? $module : $GLOBALS['modulenow'];

	if ( isset( $GLOBALS['secupress_modules'][ $module ] ) ) {
		return $GLOBALS['secupress_modules'][ $module ]['title'];
	}

	return '';
}


/**
 * Output the $text in a P tag with .description class
 *
 * @since 1.0
 *
 * @param (string)$text : the last word of the secupress page slug
*/
function __secupress_description_module( $text = '' ) { //// dans SecuPress_Settings
	if ( '' !== $text ) {
		return '<p class="description">' . $text . '</p>';
	}
}


function secupress_field( $args ) { //// dans SecuPress_Settings
	global $modulenow;

	if ( ! is_array( end( $args ) ) ) {
		$args = array( $args );
	}

	$args = array_filter( $args, 'is_array' );

	$full = $args;

	foreach ( $full as $args ) {
		if ( isset( $args['display'] ) && ! $args['display'] ) {
			continue;
		}

		$args['label_for'] = isset( $args['label_for'] )   ? $args['label_for'] : '';
		$args['name']      = isset( $args['name'] )        ? $args['name'] : $args['label_for'];
		$parent            = isset( $args['parent'] )      ? 'data-parent="' . sanitize_html_class( $args['parent'] ). '"' : null;
		$placeholder       = isset( $args['placeholder'] ) ? 'placeholder="'. $args['placeholder'].'" ' : '';
		$label             = isset( $args['label'] )       ? $args['label'] : '';
		$required          = isset( $args['required'] )    ? ' data-required="required" data-aria-required="true"' : '';
		$pattern           = isset( $args['pattern'] )     ? ' data-pattern="' . $args['pattern'] . '"' : '';
		$title             = isset( $args['title'] )       ? ' title="' . $args['title'] . '"' : '';
		$default           = isset( $args['default'] )     ? $args['default'] : '';
		$cols              = isset( $args['cols'] )        ? (int) $args['cols'] : 50;
		$rows              = isset( $args['rows'] )        ? (int) $args['rows'] : 5;
		$size              = isset( $args['size'] )        ? (int) $args['size'] : 1;
		$readonly          = ! empty( $args['readonly'] )  ? ' readonly="readonly" disabled="disabled"' : '';
		$class             = isset( $args['class'] )       ? $args['class'] : '';

		if ( is_array( $class ) ) {
			$class = implode( ' ', array_map( 'sanitize_html_class', $class ) );
		}
		else {
			$class = sanitize_html_class( $class );
		}

		$class .= ( $parent ) ? ' has-parent' : null;

		if ( ! isset( $args['fieldset'] ) || 'start' === $args['fieldset'] ) {
			echo '<fieldset class="fieldname-' . sanitize_html_class( $args['name'] ) . ' fieldtype-' . sanitize_html_class( $args['type'] ) . '">';
		}

		switch ( $args['type'] ) {
			case 'number' :
			case 'email' :
			case 'text' :

				$value = esc_attr( secupress_get_module_option( $args['name'] ) );
				if ( ! $value ) {
					$value = $default;
				}
				$min = isset( $args['min'] ) ? ' min="' . (int) $args['min'] . '"' : '';
				$max = isset( $args['max'] ) ? ' max="' . (int) $args['max'] . '"' : '';

				$number_options = $args['type'] === 'number' ? $min . $max . ' class="small-text"' : '';
				$autocomplete   = in_array( $args['name'], array( 'consumer_key', 'consumer_email' ) ) ? ' autocomplete="off"' : '';
				$disabled       = false ? ' disabled="disabled"' : $readonly;						////
				$data_realtype  = 'password' != $args['type'] ? '' : ' data-realtype="password"';
				?>
				<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
				<label>
					<input <?php echo $title; ?><?php echo $autocomplete; ?><?php echo $pattern; ?><?php echo $required; ?><?php echo $disabled; ?><?php echo $data_realtype; ?> type="<?php echo $args['type']; ?>"<?php echo $number_options; ?> id="<?php echo $args['label_for']; ?>" name="secupress_<?php echo $modulenow; ?>_settings[<?php echo $args['name']; ?>]" value="<?php echo $value; ?>" <?php echo $placeholder; ?><?php echo $readonly; ?>/>
					<?php echo $label; ?>
				</label>
				<?php
				break;

			case 'password' :

				$value        = esc_attr( secupress_get_module_option( $args['name'] ) );
				$data_nocheck = $value ? ' data-nocheck="true"' : '';
				$disabled     = false ? ' disabled="disabled"' : $readonly;
				?>
				<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
				<label>
					<input autocomplete="off" data-realtype="password" <?php echo $data_nocheck; ?><?php echo $title; ?><?php echo $pattern; ?><?php echo $required; ?><?php echo $disabled; ?> type="password" id="<?php echo $args['label_for']; ?>" name="secupress_<?php echo $modulenow; ?>_settings[<?php echo $args['name']; ?>]" value="" <?php echo $readonly; ?>/>
					<input type="text" tabindex="-1" id="password_strength_pattern"<?php echo $data_nocheck; ?> data-pattern="[3-4]" title="<?php esc_attr_e( 'Minimum Strength Level: Medium', 'secupress' ); ?>" name="secupress_<?php echo $modulenow; ?>_settings[password_strength_value]" value="0" id="password_strength_value" />
					<?php echo $label; ?>
					<i class="hide-if-no-js"><?php printf( __( 'Required: %s', 'secupress' ), _x( 'Medium', 'password strength' ) ); ?></i>
					<br><span id="password-strength" class="hide-if-no-js"></span>
				</label>
				<?php
				break;

			case 'textarea' :

				$t_temp = secupress_get_module_option( $args['name'], '' );
				$value  = ! empty( $t_temp ) ? esc_textarea( implode( "\n" , $t_temp ) ) : '';
				if ( ! $value ){
					$value = $default;
				}
				?>
				<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
				<label>
					<textarea id="<?php echo $args['label_for']; ?>" name="secupress_<?php echo $modulenow; ?>_settings[<?php echo $args['name']; ?>]" cols="<?php echo $cols; ?>" rows="<?php echo $rows; ?>"<?php echo $readonly; ?>><?php echo $value; ?></textarea>
				</label>
				<?php
				break;

			case 'checkbox' :

				if ( isset( $args['label_screen'] ) ) {
					?>
					<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
					<?php
				}
				?>
				<label>
					<input type="checkbox" id="<?php echo $args['name']; ?>" class="<?php echo $class; ?>" name="secupress_<?php echo $modulenow; ?>_settings[<?php echo $args['name']; ?>]" value="1"<?php echo $readonly; ?> <?php checked( secupress_get_module_option( $args['name'], 0 ), 1 ); ?> <?php echo $parent; ?>/> <?php echo $args['label']; ?>
				</label>
				<?php
				break;

			case 'select' : ?>

				<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
				<label>
					<select size="<?php echo $args['size']; ?>" multiple="multiple" id="<?php echo $args['name']; ?>" name="secupress_<?php echo $modulenow; ?>_settings[<?php echo $args['name']; ?>]"<?php echo $readonly; ?>>
						<?php
						foreach ( $args['options'] as $val => $title ) {
							if ( '_' === $val[0] ) {
								$title .= ' (' . __( 'Premium', 'secupress' ) . ')';
							}
							?>
							<option value="<?php echo $val; ?>" <?php selected( secupress_get_module_option( $args['name'] ) == $val || in_array( $val, secupress_get_module_option( $args['name'], array() ) ) ); ?>><?php echo $title; ?></option>
							<?php
						}
						?>
					</select>
					<?php echo $label; ?>
				</label>

				<?php
				break;

			case 'roles' :

				$roles = new WP_Roles();
				$roles = $roles->get_names();
				$roles = array_map( 'translate_user_role', $roles );
				?>
				<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
				<?php
				foreach ( $roles as $val => $title ) {
					?>
					<label>
						<input type="checkbox" name="secupress_<?php echo $modulenow; ?>_settings[<?php echo $args['name']; ?>][]" value="<?php echo $val; ?>"<?php checked( ! in_array( $val, secupress_get_module_option( $args['name'], array() ) ) ); ?>> <?php echo $title; ?>
					</label><br />
					<input type="hidden" name="secupress_<?php echo $modulenow; ?>_settings[hidden_<?php echo $args['name']; ?>][]" value="<?php echo $val; ?>">
					<?php
				}
				break;

			case 'checkboxes' : ?>

				<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
				<?php
				foreach ( $args['options'] as $val => $title ) {
					if ( '_' === $val[0] ) {
						$title .= ' (' . __( 'Premium', 'secupress' ) . ')';
					}
					?>
					<label>
						<input type="checkbox" id="<?php echo $args['name']; ?>_<?php echo $val; ?>" value="<?php echo $val; ?>"<?php checked( in_array( $val, (array) secupress_get_module_option( $args['name'] ) ) ); ?> name="secupress_<?php echo $modulenow; ?>_settings[<?php echo $args['name']; ?>][]"<?php echo $readonly; ?>> <?php echo $title; ?>
					</label><br />
					<?php
				}

				break;

			case 'radio' : ?>

				<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
				<?php
				foreach ( $args['options'] as $val => $title ) {
					if ( '_' === $val[0] ) {
						$title .= ' (' . __( 'Premium', 'secupress' ) . ')';
					}
					?>
					<label>
						<input type="radio" id="<?php echo $args['name']; ?>_<?php echo $val; ?>" value="<?php echo $val; ?>"<?php checked( secupress_get_module_option( $args['name'] ), $val ); ?> name="secupress_<?php echo $modulenow; ?>_settings[<?php echo $args['name']; ?>]"<?php echo $readonly; ?>> <?php echo $title; ?>
					</label><br />
					<?php
				}

				break;

			case 'nonlogintimeslot' : ?>

				<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
				<?php
				$value       = secupress_get_module_option( $args['name'] );
				$from_hour   = isset( $value['from_hour'] ) ? $value['from_hour'] : '';
				$from_minute = isset( $value['from_minute'] ) ? $value['from_minute'] : '';
				$to_hour     = isset( $value['to_hour'] ) ? $value['to_hour'] : '';
				$to_minute   = isset( $value['to_minute'] ) ? $value['to_minute'] : '';

				_e( 'Everyday', 'secupress' ); ////
				echo '<br>';
				echo '<span style="display:inline-block;min-width:3em">' . _x( 'From', '*From* xx h xx mn To xx h xx mn', 'secupress' ) . '</span>';
				?>
				<label>
					<input type="number" class="small-text" min="0" max="23" id="<?php echo $args['name']; ?>_from_hour" value="<?php echo (int) $from_hour; ?>" name="secupress_<?php echo $modulenow; ?>_settings[<?php echo $args['name']; ?>][from_hour]"<?php echo $readonly; ?>>
				</label> <?php _ex( 'h', 'hour', 'secupress' ); ?>
				<label>
					<input type="number" class="small-text" min="0" max="45" step="15" id="<?php echo $args['name']; ?>_from_minute" value="<?php echo (int) $from_minute; ?>" name="secupress_<?php echo $modulenow; ?>_settings[<?php echo $args['name']; ?>][from_minute]"<?php echo $readonly; ?>>
				</label> <?php _ex( 'min', 'minute', 'secupress' ); ?>
				<br>
				<?php
				echo '<span style="display:inline-block;min-width:3em">' . _x( 'To', 'From xx h xx mn *To* xx h xx mn', 'secupress' ) . '</span>';
				?>
				<label>
					<input type="number" class="small-text" min="0" max="23" id="<?php echo $args['name']; ?>_to_hour" value="<?php echo (int) $to_hour; ?>" name="secupress_<?php echo $modulenow; ?>_settings[<?php echo $args['name']; ?>][to_hour]"<?php echo $readonly; ?>>
				</label> <?php _ex( 'h', 'hour', 'secupress' ); ?>
				<label>
					<input type="number" class="small-text" min="0" max="45" step="15" id="<?php echo $args['name']; ?>_to_minute" value="<?php echo (int) $to_minute; ?>" name="secupress_<?php echo $modulenow; ?>_settings[<?php echo $args['name']; ?>][to_minute]"<?php echo $readonly; ?>>
				</label> <?php _ex( 'min', 'minute', 'secupress' ); ?>
				<?php

				break;

			case 'helper_description' :

				$description = isset( $args['description'] ) ? '<p class="description desc ' . $class . '">' . $args['description'] . '</p>' : '';
				echo apply_filters( 'secupress_help', $description, $args['name'], 'description' );

				break;

			case 'helper_help' :

				$description = isset( $args['description'] ) ? '<p class="description help ' . $class . '">' . $args['description'] . '</p>' : '';
				echo apply_filters( 'secupress_help', $description, $args['name'], 'help' );

			break;

			case 'helper_warning' :

				$description = isset( $args['description'] ) ? '<p class="description warning ' . $class . '"><b>' . __( 'Warning: ', 'secupress' ) . '</b>' . $args['description'] . '</p>' : '';
				echo apply_filters( 'secupress_help', $description, $args['name'], 'warning' );

				break;
			/*
			case 'secupress_export_form' : ?>

				<a href="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=secupress_export' ), 'secupress_export' ); ?>" id="export" class="button button-secondary secupressicon"><?php _e( 'Download options', 'secupress' ); ?></a>
				<?php
				break;

			case 'secupress_import_upload_form' :

				secupress_import_upload_form( 'secupress_importer' );

				break;
			*/
			default :

				echo 'Type manquant ou incorrect'; // ne pas traduire

		}

		if ( ! isset( $args['fieldset'] ) || 'end' == $args['fieldset'] ) {
			echo '</fieldset>';
		}

	}

}


/**
 * Used to display buttons on settings form, tools tab
 *
 * @since 1.0
 */
function secupress_button( $args ) { //// dans SecuPress_Settings

	$button       = $args['button'];
	$desc         = isset( $args['helper_description'] ) ? $args['helper_description'] : null;
	$help         = isset( $args['helper_help'] )        ? $args['helper_help'] : null;
	$warning      = isset( $args['helper_warning'] )     ? $args['helper_warning'] : null;
	$id           = isset( $button['button_id'] )        ? ' id="' . sanitize_html_class( $button['button_id'] ) . '"' : null;
	$button_style = isset( $button['style'] )            ? 'button-' . sanitize_html_class( $button['style'] ) : 'button-secondary';
	$class        = sanitize_html_class( strip_tags( $button['button_label'] ) );

	if ( ! empty( $help ) ) {
		$help = '<p class="description help ' . $class . '">' . $help['description'] . '</p>';
	}
	if ( ! empty( $desc ) ) {
		$desc = '<p class="description desc ' . $class . '">' . $desc['description'] . '</p>';
	}
	if ( ! empty( $warning ) ) {
		$warning = '<p class="description warning file-error ' . $class . '"><b>' . __( 'Warning: ', 'secupress' ) . '</b>' . $warning['description'] . '</p>';
	}
	?>
	<fieldset class="toto fieldname-<?php echo $class; ?> fieldtype-button">
		<?php
		if ( isset( $button['url'] ) ) {
			echo '<a href="' . esc_url( $button['url'] ) . '"' . $id . ' class="' . $button_style . ' secupressicon secupressicon-'. $class . '">' . wp_kses_post( $button['button_label'] ) . '</a>';
		}
		else {
			echo '<button' . $id . ' class="' . $button_style . ' secupressicon secupressicon-' . $class . '">' . wp_kses_post( $button['button_label'] ) . '</button>';
		}

		echo apply_filters( 'secupress_help', $desc,    sanitize_key( strip_tags( $button['button_label'] ) ), 'description' );
		echo apply_filters( 'secupress_help', $help,    sanitize_key( strip_tags( $button['button_label'] ) ), 'help' );
		echo apply_filters( 'secupress_help', $warning, sanitize_key( strip_tags( $button['button_label'] ) ), 'warning' );
		?>
	</fieldset>
	<?php
}


function __secupress_module_switch_description( $section ) {//// dans SecuPress_Settings
	global $modulenow, $sectionnow, $wp_settings_sections;

	$output = '';

	switch ( $modulenow . '_' . $sectionnow ) {
		case 'users_login_login_auth':
			$output = __( 'A Double Authentication is a way to enforce another layer of login, like an additional password, a secret key, a special link sent by email etc. Not just your login and password.', 'secupress' );
			break;
		case 'plugins_themes_plugins_themes':
			$output = __( 'By using these protections, you can easily select the proper allowed actions on your plugins.', 'secupress' );
			break;
		case 'plugins_themes_themes_plugins':
			$output = __( 'By using these protections, you can easily select the proper allowed actions on your themes.', 'secupress' );
			break;
		case 'sensitive_data_profile_protect':
			$output = __( 'Your profile can contain sensitive data and is also used to change your password. Don\'t let anyone sneaking into it.', 'secupress' );
			break;
	}

	if ( $output ) {
		echo '<div class="notice notice-success"><i>';
			echo $output;
		echo '</i></div>';
	}
}


function secupress_add_settings_section( $title, $args = null ) {//// dans SecuPress_Settings
	global $sectionnow, $modulenow, $pluginnow, $wp_settings_sections;

	$args       = wp_parse_args( $args, array( 'with_roles' => false, 'with_save_button' => true ) );
	$actions    = '';
	$section_id = 'module_' . $modulenow . '_' . $sectionnow;

	if ( ! empty( $args['with_roles'] ) ) {
		$actions .= '<button type="button" class="hide-if-no-js no-button button-actions-title" aria-expanded="false" aria-controls="block-_affected_role">' . __( 'Roles', 'secupress' ) . ' <span class="dashicons dashicons-arrow-right" aria-hidden="true"></span></button>';
	}

	do_action( 'before_section_' . $sectionnow );

	add_settings_section(
		$section_id,
		$title . $actions,
		'__secupress_module_switch_description',
		$section_id
	);

	if ( empty( $args['with_roles'] ) ) {
		return;
	}

	secupress_add_settings_field(
		'<span class="dashicons dashicons-groups"></span> ' . __( 'Affected Roles', 'secupress' ),
		array(
			'description' => __( 'Which roles will be affected by this module?', 'secupress' ),
			'field_type'  => 'field',
			'name'        => 'affected_role',
		),
		array(
			'class' => __secupress_get_hidden_classes( 'hide-if-js block-_affected_role block-plugin_' . $pluginnow ),
			array(
				'type'         => 'roles',
				'default'      => array(), //// (TODO) not supported yet why not $args['with_roles']
				'name'         => $pluginnow . '_affected_role',
				'label_for'    => $pluginnow . '_affected_role',
				'label'        => '',
				'label_screen' => __( 'Affected Roles', 'secupress' ),
			),
			array(
				'type'         => 'helper_description',
				'name'         => $pluginnow . '_affected_role',
				'description'  => __( 'Future roles will be automatically checked.', 'secupress' )
			),
			array(
				'type'         => 'helper_warning',
				'name'         => $pluginnow . '_affected_role',
				'class'        => 'hide-if-js',
				'description'  => __( 'Select 1 role minimum', 'secupress' )
			),
		)
	);
}


function secupress_add_settings_field( $title, $args, $fields ) {//// dans SecuPress_Settings
	global $sectionnow, $modulenow, $pluginnow;

	$args = wp_parse_args( $args, array( 'name' => '', 'field_type' => 'field', 'description' => '' ) );

	add_settings_field(
		'module_' . $modulenow . '_' . $pluginnow . '_' . $args['name'],
		$title . __secupress_description_module( $args['description'] ),
		'secupress_' . $args['field_type'],
		'module_' . $modulenow . '_' . $sectionnow,
		'module_' . $modulenow . '_' . $sectionnow,
		$fields
	);

	do_action( 'after_module_' . $modulenow . '_' . $pluginnow );
}


function secupress_do_secupress_settings_sections() {//// dans SecuPress_Settings_Module
	global $sectionnow, $modulenow;

	do_secupress_settings_sections( 'module_' . $modulenow . '_' . $sectionnow );
	secupress_submit_button( 'primary small', $sectionnow . '_submit' );
	do_action( 'after_section_' . $sectionnow );
}


//// Not sure this is the right place for you to be, buddy.

function secupress_submit_button( $type = 'primary large', $name = 'main_submit', $wrap = true, $other_attributes = null, $echo = true ) {//// dans SecuPress_Settings
	if ( true === $wrap ) {
		$wrap = '<p class="submit">';
	} elseif ( $wrap ) {
		$wrap = '<p class="submit ' . sanitize_html_class( $wrap ) . '">';
	}

	$button = get_submit_button( __( 'Save All Changes', 'secupress' ), $type, $name, false, $other_attributes );

	if ( $wrap ) {
		$button = $wrap . $button . '</p>';
	}

	if ( ! $echo ) {
		return $button;
	}

	echo $button;
}


function do_secupress_settings_sections( $page ) {//// dans SecuPress_Settings
	return;
	echo '<div class="secublock">';
		do_settings_sections( $page );
	echo '</div>';
}


function __secupress_get_hidden_classes( $classes ) {//// dans SecuPress_Settings
	$output = 'hide-if-js block-hidden ' . $classes;
	return $output;
}


function secupress_load_settings( $module, $plugin ) { //// dans SecuPress_Settings
	$plugin_file = SECUPRESS_MODULES_PATH . sanitize_key( $module ) . '/settings/' . sanitize_key( $plugin ) . '.php';

	if ( file_exists( $plugin_file ) ) {
		require( $plugin_file );
	}
}
