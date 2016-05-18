<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );


/**
 * Base class for settings.
 *
 * @package SecuPress
 * @since 1.0
 */
abstract class SecuPress_Settings extends SecuPress_Singleton {

	const VERSION = '1.0';

	/**
	 * Current module: corresponds to the page tab, like `users_login`.
	 *
	 * @var (string)
	 */
	protected $modulenow;

	/**
	 * Current section: corresponds to a block, like `login_auth`.
	 *
	 * @var (string)
	 */
	protected $sectionnow;

	/**
	 * Current plugin (or sub-module): corresponds to a field, like `captcha`.
	 *
	 * @var (string)
	 */
	protected $pluginnow;

	/**
	 * Section descriptions.
	 *
	 * @var (array)
	 */
	protected $section_descriptions = array();

	/**
	 * Section Save buttons.
	 *
	 * @var (array)
	 */
	protected $section_save_buttons = array();

	/**
	 * Form action attribute (URL).
	 *
	 * @var (string)
	 */
	protected $form_action;

	/**
	 * Tells if the current module should be wrapped in a form.
	 *
	 * @var (bool)
	 */
	protected $with_form = true;


	// Setters =====================================================================================.

	/**
	 * Set the current module.
	 *
	 * @since 1.0
	 *
	 * @return (object) The class instance.
	 */
	protected function set_current_module() {
		die( 'Method SecuPress_Settings::set_current_module() must be over-ridden in a sub-class.' );
		return $this;
	}


	/**
	 * Set the current section.
	 *
	 * @since 1.0
	 *
	 * @param (string) $section The section to set.
	 *
	 * @return (object) The class instance.
	 */
	final protected function set_current_section( $section ) {
		$this->sectionnow = $section;
		return $this;
	}


	/**
	 * Set the current plugin.
	 *
	 * @since 1.0
	 *
	 * @param (string) $plugin The plugin to set.
	 *
	 * @return (object) The class instance.
	 */
	final protected function set_current_plugin( $plugin ) {
		$this->pluginnow = $plugin;
		return $this;
	}


	/**
	 * Set the current section description.
	 *
	 * @since 1.0
	 *
	 * @param (string) $description The description to set.
	 *
	 * @return (object) The class instance.
	 */
	final protected function set_section_description( $description ) {
		$section_id = $this->modulenow . '|' . $this->sectionnow;

		$this->section_descriptions[ $section_id ] = $description;

		return $this;
	}


	/**
	 * Tell if the current section should display a Save button.
	 *
	 * @since 1.0
	 *
	 * @param (bool) $value True to display the button. False to hide it.
	 *
	 * @return (object) The class instance.
	 */
	final protected function set_section_save_button( $value ) {
		$section_id = $this->get_section_id();

		if ( $value ) {
			$this->section_save_buttons[ $section_id ] = 1;
		} else {
			unset( $this->section_save_buttons[ $section_id ] );
		}

		return $this;
	}


	// Getters =====================================================================================.

	/**
	 * Get the current module.
	 *
	 * @since 1.0
	 *
	 * @return (string) The current module.
	 */
	final public function get_current_module() {
		return $this->modulenow;
	}


	/**
	 * Get the current section.
	 *
	 * @since 1.0
	 *
	 * @return (string) The current section.
	 */
	final public function get_current_section() {
		return $this->sectionnow;
	}


	/**
	 * Get the current plugin.
	 *
	 * @since 1.0
	 *
	 * @return (string) The current plugin.
	 */
	final public function get_current_plugin() {
		return $this->pluginnow;
	}


	/**
	 * Get the current section ID.
	 *
	 * @since 1.0
	 *
	 * @return (string) The current section ID.
	 */
	public function get_section_id() {
		return 'module_' . $this->modulenow . '|' . $this->sectionnow;
	}


	/**
	 * Get the form action attribute (URL).
	 *
	 * @since 1.0
	 *
	 * @return (string) The attribute.
	 */
	final public function get_form_action() {
		return $this->form_action;
	}


	/**
	 * Tells if the current module should be wrapped in a form.
	 *
	 * @since 1.0
	 *
	 * @return (bool)
	 */
	final public function get_with_form() {
		return $this->with_form;
	}


	// Init ========================================================================================.

	/**
	 * Init: this method is required by the class `SecuPress_Singleton`.
	 *
	 * @since 1.0
	 */
	protected function _init() {
		$this->set_current_module();

		$this->form_action = is_network_admin() ? admin_url( 'admin-post.php' ) : admin_url( 'options.php' );
		$this->form_action = esc_url( $this->form_action );
	}


	// Sections ====================================================================================.

	/**
	 * Add a section in the page (a block).
	 *
	 * @since 1.0
	 *
	 * @param (string) $title The section title.
	 * @param (array)  $args  An array allowing 2 parameters:
	 *                        - (bool) $with_roles       Whenever to display a "Affected roles" radios list.
	 *                        - (bool) $with_save_button Whenever to display a "Save Settings" button.
	 *
	 * @return (object) The class instance.
	 */
	protected function add_section( $title, $args = null ) {
		static $i = 0;

		$args       = wp_parse_args( $args, array( 'with_roles' => false, 'with_save_button' => true ) );
		$actions    = '';
		$section_id = $this->get_section_id();

		if ( ! empty( $args['with_roles'] ) ) {
			$actions .= '<button type="button" id="affected-role-' . $i . '" class="hide-if-no-js no-button button-actions-title">' . __( 'Roles', 'secupress' ) . ' <span class="dashicons dashicons-arrow-right" aria-hidden="true"></span></button>';
		}

		add_settings_section(
			$section_id,
			$title . $actions,
			array( $this, 'print_section_description' ),
			$section_id
		);

		if ( (bool) $args['with_save_button'] ) {
			$this->section_save_buttons[ $section_id ] = 1;
		}

		if ( ! $args['with_roles'] ) {
			return $this;
		}

		$this->add_field( array(
			'title'        => '<span class="dashicons dashicons-groups"></span> ' . __( 'Affected Roles', 'secupress' ),
			'description'  => __( 'Which roles will be affected by this module?', 'secupress' ),
			'depends'      => 'affected-role-' . $i,
			'row_class'    => 'affected-role-row',
			'name'         => $this->get_field_name( 'affected_role' ),
			'type'         => 'roles',
			'label_screen' => __( 'Affected Roles', 'secupress' ),
			'helpers'      => array(
				array(
					'type'        => 'description',
					'description' => __( 'Future roles will be automatically checked.', 'secupress' ),
				),
				array(
					'type'        => 'warning',
					'class'       => 'hide-if-js',
					'description' => __( 'Select 1 role minimum', 'secupress' ),
				),
			),
		) );

		++$i;

		return $this;
	}


	/**
	 * A wrapper for `$this->do_settings_sections()` that wraps the sections in a `<div>` tag and prints the "Save" button.
	 *
	 * @since 1.0
	 *
	 * @return (object) The class instance.
	 */
	protected function do_sections() {

		$section_id       = $this->get_section_id();
		$html_id          = explode( '|', $section_id );
		$html_id          = sanitize_html_class( implode( '--', $html_id ) );
		$with_save_button = ! empty( $this->section_save_buttons[ $section_id ] );

		echo '<div class="secupress-settings-section" id="secupress-settings-' . $html_id . '">';

		/**
		 * Fires before a section.
		 *
		 * @since 1.0
		 *
		 * @param (bool) $with_save_button True if a "Save All Changes" button will be printed.
		 */
		do_action( 'secupress.settings.before_section_' . $this->sectionnow, $with_save_button );

		echo '<div class="secublock">';
			$this->do_settings_sections();
		echo '</div><!-- .secublock -->';

		if ( $with_save_button ) {
			static::submit_button( 'primary', $this->sectionnow . '_submit' );
		}

		/**
		 * Fires after a section.
		 *
		 * @since 1.0
		 *
		 * @param (bool) $with_save_button True if a "Save All Changes" button will be printed.
		 */
		do_action( 'secupress.settings.after_section_' . $this->sectionnow, $with_save_button );

		echo '</div><!-- #secupress-settings-' . $html_id . ' -->';

		return $this;
	}


	/**
	 * Like the real `do_settings_sections()` but using a custom `do_settings_fields()`.
	 *
	 * @since 1.0
	 */
	final protected function do_settings_sections() {
		global $wp_settings_sections, $wp_settings_fields;

		$section_id = $this->get_section_id();

		if ( ! isset( $wp_settings_sections[ $section_id ] ) ) {
			return;
		}

		foreach ( (array) $wp_settings_sections[ $section_id ] as $section ) {

			$header_open_tag = false;

			if ( $section['title'] ) {
				echo '<div class="secupress-settings-section-header">';
				$header_open_tag = true;
				$id = explode( '|', $section['id'] );
				$id = end( $id );
				echo '<h3 class="secupress-settings-section-title" id="module-' . sanitize_html_class( $id ) . '">' . $section['title'] . '</h3>' . "\n";
			}

			if ( $section['callback'] ) {
				echo ( $header_open_tag ? '' : '<div class="secupress-settings-section-header">' );
				$header_open_tag = true;
				call_user_func( $section['callback'], $section );
			}

			echo ( $header_open_tag ? '</div><!-- .secupress-settings-section-header -->' : '' );

			if ( ! isset( $wp_settings_fields ) || ! isset( $wp_settings_fields[ $section_id ] ) || ! isset( $wp_settings_fields[ $section_id ][ $section['id'] ] ) ) {
				continue;
			}

			echo '<div class="secupress-form-table">';
				static::do_settings_fields( $section_id, $section['id'] );
			echo '</div>';
		}
	}


	// Generic fields ==============================================================================.

	/**
	 * The main callback that prints basic fields.
	 *
	 * @since 1.0
	 *
	 * @param (array) $args An array with the following parameters:
	 *                - (string) $type              The field type: 'number', 'email', 'tel', 'text', 'textarea', 'select', 'checkbox', 'checkboxes', 'radioboxes', 'radios', 'roles', 'countries', 'nonlogintimeslot'.
	 *                - (string) $name              The name attribute. Also used as id attribute if `$label_for` is not provided.
	 *                - (string) $label_for         The id attribute. Also used as name attribute if `$name` is not provided.
	 *                - (bool)   $plugin_activation Set to true if the field is not used for a setting but to (de)activate a plugin.
	 *                - (mixed)  $default           The default value.
	 *                - (mixed)  $value             The field value. If not provided the field will look for an option stored in db.
	 *                - (array)  $options           Used for 'select', 'checkboxes', 'radioboxes' and 'radios': all possible choices for the user (value => label).
	 *                - (string) $fieldset          Wrap the field in a `<fieldset>` tag. Possible values: 'start', 'end', 'no' and 'yes'. 'checkboxes', 'radioboxes' and 'radios' are automatically wrapped. 'start' and 'end' are not used yet.
	 *                - (string) $label_screen      Used for the `<legend>` tag when a fieldset is used.
	 *                - (string) $label             A label to display on top of the field. Also used as field label for the 'checkbox' type.
	 *                - (string) $label_before      A label to display before the field.
	 *                - (string) $label_after       A label to display after the field.
	 *                - (bool)   $disabled          True to disable the field. Pro fields are automatically disabled on the free version.
	 *                - (array)  $attributes        An array of html attributes to add to the field (like min and max for a 'number' type).
	 *                - (array)  $helpers           An array containing the helpers. See `self::helpers()`.
	 */
	protected function field( $args ) {
		$args = array_merge( array(
			'type'              => '',
			'name'              => '',
			'label_for'         => '',
			'plugin_activation' => false,
			'default'           => '',
			'value'             => null,
			'options'           => array(),
			'fieldset'          => null,
			'label_screen'      => '',
			'label'             => '',
			'label_before'      => '',
			'label_after'       => '',
			'disabled'          => false,
			'attributes'        => array(),
			'helpers'           => array(),
		), $args );

		if ( $args['plugin_activation'] ) {
			$option_name = 'secupress-plugin-activation';
		} else {
			$option_name = 'secupress' . ( 'global' !== $this->modulenow ? '_' . $this->modulenow : '' ) . '_settings';
		}
		$name_attribute = $option_name . '[' . $args['name'] . ']';
		$disabled       = ! empty( $args['disabled'] ) || static::is_pro_feature( $args['name'] );

		// Type.
		$args['type'] = 'radio' === $args['type'] ? 'radios' : $args['type'];

		// Value.
		if ( isset( $args['value'] ) ) {
			$value = $args['value'];
		} elseif ( 'global' === $this->modulenow ) {
			$value = secupress_get_option( $args['name'] );
		} else {
			$value = secupress_get_module_option( $args['name'] );
		}

		if ( is_null( $value ) ) {
			$value = $args['default'];
		}

		// HTML attributes.
		$args['label_for'] = $args['label_for'] ? $args['label_for'] : $args['name'];
		$args['label_for'] = esc_attr( $args['label_for'] );

		$attributes = '';
		$args['attributes']['class'] = ! empty( $args['attributes']['class'] ) ? (array) $args['attributes']['class'] : array();

		if ( 'radioboxes' === $args['type'] || 'checkboxes' === $args['type'] || 'checkbox' === $args['type'] || 'roles' === $args['type'] ) {
			$args['attributes']['class'][] = 'secupress-checkbox';
		}
		if ( 'countries' === $args['type'] ) {
			$args['attributes']['class'][] = 'secupress-checkbox';
			$args['attributes']['class'][] = 'secupress-checkbox-mini';
		}

		if ( 'radios' === $args['type'] ) {
			$args['attributes']['class'][] = 'secupress-radio';
		}

		if ( 'number' === $args['type'] ) {
			$args['attributes']['class'][] = 'small-text';
		} elseif ( 'radioboxes' === $args['type'] ) {
			$args['attributes']['class'][] = 'radiobox';
		}

		if ( $args['attributes']['class'] ) {
			$args['attributes']['class'] = implode( ' ', array_map( 'sanitize_html_class', $args['attributes']['class'] ) );
		} else {
			unset( $args['attributes']['class'] );
		}

		if ( ! empty( $args['attributes']['pattern'] ) ) {
			$args['attributes']['data-pattern'] = $args['attributes']['pattern'];
		}

		if ( ! empty( $args['attributes']['required'] ) ) {
			$args['attributes']['data-required']      = 'required';
			$args['attributes']['data-aria-required'] = 'true';
		}

		if ( $disabled ) {
			$args['attributes']['disabled'] = 'disabled';
		}

		unset( $args['attributes']['pattern'], $args['attributes']['required'] );

		if ( ! empty( $args['attributes'] ) ) {
			foreach ( $args['attributes'] as $attribute => $attribute_value ) {
				$attributes .= ' ' . $attribute . '="' . esc_attr( $attribute_value ) . '"';
			}
		}

		// Fieldset.
		$has_fieldset_begin = false;
		$has_fieldset_end   = false;

		switch ( $args['fieldset'] ) {
			case 'start' :
				$has_fieldset_begin = true;
				break;
			case 'end' :
				$has_fieldset_end = true;
				break;
			case 'no' :
				break;
			default :
				$fieldset_auto = array( 'checkboxes' => 1, 'radioboxes' => 1, 'radios' => 1, 'roles' => 1 );

				if ( 'yes' === $args['fieldset'] || isset( $fieldset_auto[ $args['type'] ] ) ) {
					$has_fieldset_begin = true;
					$has_fieldset_end   = true;
				}
		}

		if ( $has_fieldset_begin ) {
			echo '<fieldset class="fieldname-' . sanitize_html_class( $args['name'] ) . ' fieldtype-' . sanitize_html_class( $args['type'] ) . '">';

			if ( ! empty( $args['label_screen'] ) ) {
				echo '<legend class="screen-reader-text"><span>' . $args['label_screen'] . '</span></legend>';
			}
		}

		// Labels.
		$label_open  = '';
		$label_close = '';
		if ( '' !== $args['label_before'] || '' !== $args['label'] || '' !== $args['label_after'] ) {
			$label_open  = '<label' . ( $disabled ? ' class="disabled"' : '' ) . '>';
			$label_close = '</label>';
		}

		// Types.
		switch ( $args['type'] ) {
			case 'number' :
			case 'email' :
			case 'tel' :
			case 'url' :
			case 'text' :

				echo $label_open; ?>
					<?php
					echo $args['label'] ? $args['label'] . '<br/>' : '';
					echo $args['label_before'];
					echo '<input type="' . $args['type'] . '" id="' . $args['label_for'] . '" name="' . $name_attribute . '" value="' . esc_attr( $value ) . '"' . $attributes . '/>';
					echo $args['label_after'];
					?>
				<?php
				echo $label_close;
				break;

			case 'textarea' :

				$value       = esc_textarea( implode( "\n" , (array) $value ) );
				$attributes .= empty( $args['attributes']['cols'] ) ? ' cols="50"' : '';
				$attributes .= empty( $args['attributes']['rows'] ) ? ' rows="5"'  : '';

				echo $label_open; ?>
					<?php
					echo $args['label'] ? '<span class="secupress-bold">' . $args['label'] . '</span><br/>' : '';
					echo $args['label_before'];
					echo '<div class="secupress-textarea-container"><textarea id="' . $args['label_for'] . '" name="' . $name_attribute . '"' . $attributes . '>' . $value . '</textarea></div>';
					echo $args['label_after'];
					?>
				<?php
				echo $label_close;
				break;

			case 'select' :

				$value = array_flip( (array) $value );
				$has_disabled = false;

				echo $label_open; ?>
					<?php
					echo $args['label'] ? $args['label'] . '<br/>' : '';
					echo $args['label_before'];
					?>
					<select id="<?php echo $args['label_for']; ?>" name="<?php echo $name_attribute; ?>"<?php echo $attributes; ?>>
						<?php
						foreach ( $args['options'] as $val => $title ) {
							$disabled = '';
							if ( static::is_pro_feature( $args['name'] . '|' . $val ) ) {
								$disabled     = ' disabled="disabled"';
								$has_disabled = true;
							}
							?>
							<option value="<?php echo $val; ?>"<?php selected( isset( $value[ $val ] ) ); ?><?php echo $disabled; ?>><?php echo $title . ( $disabled ? ' (*)' : '' ); ?></option>
							<?php
						}
						?>
					</select>
					<?php
					echo $args['label_after'];
					?>
				<?php
				echo $label_close;

				echo $has_disabled ? static::get_pro_version_string( '<span class="description">(*) %s</span>' ) : '';

				break;

			case 'checkbox' :

				echo '<p class="secupress-checkbox-line">';
				echo $label_open; ?>
					<?php
					echo $args['label_before'];
					echo '<input type="checkbox" id="' . $args['label_for'] . '" name="' . $name_attribute . '" value="1"' . checked( $value, 1, false ) . $attributes . ' class="secupress-checkbox" />';
					echo '<span class="label-text">' . $args['label'] . '</span>';
					?>
				<?php echo $label_close;
				echo '</p>';
				break;

			case 'checkboxes' :
			case 'radioboxes' :

				$value = array_flip( (array) $value );

				foreach ( $args['options'] as $val => $title ) {
					$args['label_for'] = $args['name'] . '_' . $val;
					$disabled          = static::is_pro_feature( $args['name'] . '|' . $val ) ? ' disabled="disabled"' : '';
					?>
					<p class="secupress-fieldset-item secupress-fieldset-item-<?php echo $args['type']; ?><?php echo static::is_pro_feature( $args['name'] . '|' . $val ) ? ' secupress-pro-option' : ''; ?>">
						<label<?php echo $disabled ? ' class="disabled"' : ''; ?> for="<?php echo esc_attr( $args['label_for'] ); ?>">
							<input type="checkbox" id="<?php echo $args['label_for']; ?>" name="<?php echo $name_attribute; ?>[]" value="<?php echo $val; ?>"<?php checked( isset( $value[ $val ] ) ); ?><?php echo $disabled; ?><?php echo $attributes; ?>>
							<?php echo '<span class="label-text">' . $title . '</span>'; ?>
						</label>
					<?php echo static::is_pro_feature( $args['name'] . '|' . $val ) ? static::get_pro_version_string( '<span class="description secupress-get-pro-version">%s</span>' ) : ''; ?>
					</p>
					<?php
				}
				break;

			case 'radios' : // Video killed the radio star.

				foreach ( $args['options'] as $val => $title ) {
					$args['label_for'] = $args['name'] . '_' . $val;
					$disabled          = static::is_pro_feature( $args['name'] . '|' . $val ) ? ' disabled="disabled"' : '';
					?>
					<p class="secupress-radio-line<?php echo static::is_pro_feature( $args['name'] . '|' . $val ) ? ' secupress-pro-option' : ''; ?>">
						<label<?php echo $disabled ? ' class="disabled"' : ''; ?> for="<?php echo esc_attr( $args['label_for'] ); ?>">
							<input type="radio" id="<?php echo $args['label_for']; ?>" name="<?php echo $name_attribute; ?>" value="<?php echo $val; ?>"<?php checked( $value, $val ); ?><?php echo $disabled; ?><?php echo $attributes; ?>>
							<?php echo '<span class="label-text">' . $title . '</span>'; ?>
						</label>
						<?php echo static::is_pro_feature( $args['name'] . '|' . $val ) ? static::get_pro_version_string( '<span class="description secupress-get-pro-version">%s</span>' ) : ''; ?>
					</p>
					<?php
				}
				break;

			case 'roles' :

				$value = array_flip( (array) $value );
				$roles = new WP_Roles();
				$roles = $roles->get_names();
				$roles = array_map( 'translate_user_role', $roles );

				foreach ( $roles as $val => $title ) {
					?>
					<p class="secupress-checkbox-roles-line">
						<label<?php echo $disabled ? ' class="disabled"' : ''; ?>>
							<input type="checkbox" name="<?php echo $name_attribute; ?>[]" value="<?php echo $val; ?>"<?php checked( ! isset( $value[ $val ] ) ); ?><?php echo $attributes; ?>>
							<?php echo '<span class="label-text">' . $title . '</span>'; ?>
						</label>
					</p>
					<?php
				}
				break;

			case 'countries' :
				$value          = array_flip( (array) array_filter( $value ) );
				$disabled_class = $disabled ? ' disabled' : '';
				$disabled_attr  = $disabled ? ' class="disabled"' : '';
				$_countries     = array( 'AF' => array( 0 => 'Africa', 'AO' => 'Angola', 'BF' => 'Burkina Faso', 'BI' => 'Burundi', 'BJ' => 'Benin', 'BW' => 'Botswana', 'CD' => 'Congo, The Democratic Republic of the', 'CF' => 'Central African Republic', 'CG' => 'Congo', 'CI' => 'Cote D\'Ivoire', 'CM' => 'Cameroon', 'CV' => 'Cape Verde', 'DJ' => 'Djibouti', 'DZ' => 'Algeria', 'EG' => 'Egypt', 'EH' => 'Western Sahara', 'ER' => 'Eritrea', 'ET' => 'Ethiopia', 'GA' => 'Gabon', 'GH' => 'Ghana', 'GM' => 'Gambia', 'GN' => 'Guinea', 'GQ' => 'Equatorial Guinea', 'GW' => 'Guinea-Bissau', 'KE' => 'Kenya', 'KM' => 'Comoros', 'LR' => 'Liberia', 'LS' => 'Lesotho', 'LY' => 'Libya', 'MA' => 'Morocco', 'MG' => 'Madagascar', 'ML' => 'Mali', 'MR' => 'Mauritania', 'MU' => 'Mauritius', 'MW' => 'Malawi', 'MZ' => 'Mozambique', 'NA' => 'Namibia', 'NE' => 'Niger', 'NG' => 'Nigeria', 'RE' => 'Reunion', 'RW' => 'Rwanda', 'SC' => 'Seychelles', 'SD' => 'Sudan', 'SH' => 'Saint Helena', 'SL' => 'Sierra Leone', 'SN' => 'Senegal', 'SO' => 'Somalia', 'ST' => 'Sao Tome and Principe', 'SZ' => 'Swaziland', 'TD' => 'Chad', 'TG' => 'Togo', 'TN' => 'Tunisia', 'TZ' => 'Tanzania, United Republic of', 'UG' => 'Uganda', 'YT' => 'Mayotte', 'ZA' => 'South Africa', 'ZM' => 'Zambia', 'ZW' => 'Zimbabwe', 'SS' => 'South Sudan' ), 'AN' => array( 0 => 'Antarctica', 'AQ' => 'Antarctica', 'BV' => 'Bouvet Island', 'GS' => 'South Georgia and the South Sandwich Islands', 'HM' => 'Heard Island and McDonald Islands', 'TF' => 'French Southern Territories' ), 'AS' => array( 0 => 'Asia', 'AP' => 'Asia/Pacific Region', 'AE' => 'United Arab Emirates', 'AF' => 'Afghanistan', 'AM' => 'Armenia', 'AZ' => 'Azerbaijan', 'BD' => 'Bangladesh', 'BH' => 'Bahrain', 'BN' => 'Brunei Darussalam', 'BT' => 'Bhutan', 'CC' => 'Cocos (Keeling) Islands', 'CN' => 'China', 'CX' => 'Christmas Island', 'CY' => 'Cyprus', 'GE' => 'Georgia', 'HK' => 'Hong Kong', 'ID' => 'Indonesia', 'IL' => 'Israel', 'IN' => 'India', 'IO' => 'British Indian Ocean Territory', 'IQ' => 'Iraq', 'IR' => 'Iran, Islamic Republic of', 'JO' => 'Jordan', 'JP' => 'Japan', 'KG' => 'Kyrgyzstan', 'KH' => 'Cambodia', 'KP' => 'Korea, Democratic People\'s Republic of', 'KR' => 'Korea, Republic of', 'KW' => 'Kuwait', 'KZ' => 'Kazakhstan', 'LA' => 'Lao People\'s Democratic Republic', 'LB' => 'Lebanon', 'LK' => 'Sri Lanka', 'MM' => 'Myanmar', 'MN' => 'Mongolia', 'MO' => 'Macau', 'MV' => 'Maldives', 'MY' => 'Malaysia', 'NP' => 'Nepal', 'OM' => 'Oman', 'PH' => 'Philippines', 'PK' => 'Pakistan', 'PS' => 'Palestinian Territory', 'QA' => 'Qatar', 'SA' => 'Saudi Arabia', 'SG' => 'Singapore', 'SY' => 'Syrian Arab Republic', 'TH' => 'Thailand', 'TJ' => 'Tajikistan', 'TM' => 'Turkmenistan', 'TL' => 'Timor-Leste', 'TW' => 'Taiwan', 'UZ' => 'Uzbekistan', 'VN' => 'Vietnam', 'YE' => 'Yemen' ), 'EU' => array( 0 => 'Europe', 'AD' => 'Andorra', 'AL' => 'Albania', 'AT' => 'Austria', 'BA' => 'Bosnia and Herzegovina', 'BE' => 'Belgium', 'BG' => 'Bulgaria', 'BY' => 'Belarus', 'CH' => 'Switzerland', 'CZ' => 'Czech Republic', 'DE' => 'Germany', 'DK' => 'Denmark', 'EE' => 'Estonia', 'ES' => 'Spain', 'FI' => 'Finland', 'FO' => 'Faroe Islands', 'FR' => 'France', 'GB' => 'United Kingdom', 'GI' => 'Gibraltar', 'GR' => 'Greece', 'HR' => 'Croatia', 'HU' => 'Hungary', 'IE' => 'Ireland', 'IS' => 'Iceland', 'IT' => 'Italy', 'LI' => 'Liechtenstein', 'LT' => 'Lithuania', 'LU' => 'Luxembourg', 'LV' => 'Latvia', 'MC' => 'Monaco', 'MD' => 'Moldova, Republic of', 'MK' => 'Macedonia', 'MT' => 'Malta', 'NL' => 'Netherlands', 'NO' => 'Norway', 'PL' => 'Poland', 'PT' => 'Portugal', 'RO' => 'Romania', 'RU' => 'Russian Federation', 'SE' => 'Sweden', 'SI' => 'Slovenia', 'SJ' => 'Svalbard and Jan Mayen', 'SK' => 'Slovakia', 'SM' => 'San Marino', 'TR' => 'Turkey', 'UA' => 'Ukraine', 'VA' => 'Holy See (Vatican City State)', 'RS' => 'Serbia', 'ME' => 'Montenegro', 'AX' => 'Aland Islands', 'GG' => 'Guernsey', 'IM' => 'Isle of Man', 'JE' => 'Jersey' ), 'OC' => array( 0 => 'Oceania', 'AS' => 'American Samoa', 'AU' => 'Australia', 'CK' => 'Cook Islands', 'FJ' => 'Fiji', 'FM' => 'Micronesia, Federated States of', 'GU' => 'Guam', 'KI' => 'Kiribati', 'MH' => 'Marshall Islands', 'MP' => 'Northern Mariana Islands', 'NC' => 'New Caledonia', 'NF' => 'Norfolk Island', 'NR' => 'Nauru', 'NU' => 'Niue', 'NZ' => 'New Zealand', 'PF' => 'French Polynesia', 'PG' => 'Papua New Guinea', 'PN' => 'Pitcairn Islands', 'PW' => 'Palau', 'SB' => 'Solomon Islands', 'TK' => 'Tokelau', 'TO' => 'Tonga', 'TV' => 'Tuvalu', 'UM' => 'United States Minor Outlying Islands', 'VU' => 'Vanuatu', 'WF' => 'Wallis and Futuna', 'WS' => 'Samoa' ), 'NA' => array( 0 => 'North America', 'AG' => 'Antigua and Barbuda', 'AI' => 'Anguilla', 'CW' => 'Curacao', 'AW' => 'Aruba', 'BB' => 'Barbados', 'BM' => 'Bermuda', 'BS' => 'Bahamas', 'BZ' => 'Belize', 'CA' => 'Canada', 'CR' => 'Costa Rica', 'CU' => 'Cuba', 'DM' => 'Dominica', 'DO' => 'Dominican Republic', 'SX' => 'Sint Maarten (Dutch part)', 'GD' => 'Grenada', 'GL' => 'Greenland', 'GP' => 'Guadeloupe', 'GT' => 'Guatemala', 'HN' => 'Honduras', 'HT' => 'Haiti', 'JM' => 'Jamaica', 'KN' => 'Saint Kitts and Nevis', 'KY' => 'Cayman Islands', 'LC' => 'Saint Lucia', 'MQ' => 'Martinique', 'MS' => 'Montserrat', 'MX' => 'Mexico', 'NI' => 'Nicaragua', 'PA' => 'Panama', 'PM' => 'Saint Pierre and Miquelon', 'PR' => 'Puerto Rico', 'SV' => 'El Salvador', 'TC' => 'Turks and Caicos Islands', 'TT' => 'Trinidad and Tobago', 'US' => 'United States', 'VC' => 'Saint Vincent and the Grenadines', 'VG' => 'Virgin Islands, British', 'VI' => 'Virgin Islands, U.S.', 'BL' => 'Saint Barthelemy', 'MF' => 'Saint Martin', 'BQ' => 'Bonaire, Saint Eustatius and Saba' ), 'SA' => array( 0 => 'South America', 'AR' => 'Argentina', 'BO' => 'Bolivia', 'BR' => 'Brazil', 'CL' => 'Chile', 'CO' => 'Colombia', 'EC' => 'Ecuador', 'FK' => 'Falkland Islands (Malvinas)', 'GF' => 'French Guiana', 'GY' => 'Guyana', 'PE' => 'Peru', 'PY' => 'Paraguay', 'SR' => 'Suriname', 'UY' => 'Uruguay', 'VE' => 'Venezuela' ) );

				foreach ( $_countries as $code_country => $countries ) {
					$title   = array_shift( $countries );
					$checked = array_intersect_key( $value, $countries );
					$checked = ! empty( $checked );
					?>
					<label class="continent<?php echo $disabled_class; ?>">
						<input type="checkbox" value="continent-<?php echo $code_country; ?>"<?php checked( $checked ); ?><?php echo $attributes; ?>>
						<?php echo '<span class="label-text">' . $title . '</span>'; ?>
					</label>
					<button type="button" class="hide-if-no-js expand_country"><img src="data:image/gif;base64,R0lGODlhEAAQAMQAAAAAAM/Iu3iYtcK4qPX18bDC09/b0ubm5v///9jTye3t59LMv8a+ruXh2tzYz/j4+PDw7NbRxuTh2f///wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAUUABMALAAAAAAQABAAAAVI4CSOZGmeaKqubFkIcCwUp4DcOCLUOHA/O5PgQQQ8II1gSUAAOJ0GJUkAgSgAB4lDOhJoE4DIIsAVCRaMgVpdnrxkMFprjgoBADs=" alt="+" title="<?php esc_attr__( 'Expand', 'secupress' ); ?>" /></button>
					<fieldset class="hide-if-js">
						<legend class="screen-reader-text"><span><?php echo $title; ?></span></legend>
						<?php
						foreach ( $countries as $code => $title ) {
							$args['label_for'] = $args['name'] . '_' . $code;
							?>
							<div>
								<span class="secupress-tree-dash"></span>
								<label<?php echo $disabled_attr; ?>>
									<input type="checkbox" id="<?php echo $args['label_for']; ?>" name="<?php echo $name_attribute; ?>[]" value="<?php echo $code; ?>"<?php checked( isset( $value[ $code ] ) ); ?> data-code-country="<?php echo $code_country; ?>"<?php echo $attributes; ?>>
									<?php echo '<span class="label-text">' . $title . '</span>'; ?>
								</label>
							</div>
							<?php
						}
						?>
					</fieldset>
					<br/>
					<?php
				}
				break;

			case 'time-slot' :

				$from_hour   = isset( $value['from_hour'] )   ? (int) $value['from_hour']   : 0;
				$from_minute = isset( $value['from_minute'] ) ? (int) $value['from_minute'] : 0;
				$to_hour     = isset( $value['to_hour'] )     ? (int) $value['to_hour']     : 0;
				$to_minute   = isset( $value['to_minute'] )   ? (int) $value['to_minute']   : 0;
				$attributes .= ' type="text" class="small-text" size="2" maxlength="2" autocomplete="off"';

				echo $args['label'] ? '<p id="' . $args['name'] . '-time-slot-label">' . $args['label'] . '</p>' : '';
				?>
				<fieldset aria-labelledby="<?php echo $args['name']; ?>-time-slot-label">
					<legend class="screen-reader-text"><?php _e( 'Start hour and minute', 'secupress' ); ?></legend>
					<label>
						<span class="label-before" aria-hidden="true"><?php _ex( 'From', 'starting hour + minute', 'secupress' ); ?></span>
						<span class="screen-reader-text"><?php _e( 'Hour' ); ?></span>
						<input id="<?php echo $args['name']; ?>_from_hour" name="<?php echo $name_attribute; ?>[from_hour]" value="<?php echo str_pad( $from_hour, 2, 0, STR_PAD_LEFT ); ?>" pattern="0?[0-9]|1[0-9]|2[0-3]"<?php echo $attributes; ?>>
						<span aria-hidden="true"><?php _ex( 'h', 'hour', 'secupress' ); ?></span>
					</label>
					<label>
						<span class="screen-reader-text"><?php _e( 'Minute' ); ?></span>
						<input id="<?php echo $args['name']; ?>_from_minute" name="<?php echo $name_attribute; ?>[from_minute]" value="<?php echo str_pad( $from_minute, 2, 0, STR_PAD_LEFT ); ?>" pattern="0?[0-9]|[1-5][0-9]"<?php echo $attributes; ?>>
						<span aria-hidden="true"><?php _ex( 'min', 'minute', 'secupress' ); ?></span>
					</label>
				</fieldset>

				<fieldset aria-labelledby="<?php echo $args['name']; ?>-time-slot-label">
					<legend class="screen-reader-text"><?php _e( 'End hour and minute', 'secupress' ); ?></legend>
					<label>
						<span class="label-before" aria-hidden="true"><?php _ex( 'To', 'ending hour + minute', 'secupress' ) ?></span>
						<span class="screen-reader-text"><?php _e( 'Hour' ); ?></span>
						<input id="<?php echo $args['name']; ?>_to_hour" name="<?php echo $name_attribute; ?>[to_hour]" value="<?php echo str_pad( $to_hour, 2, 0, STR_PAD_LEFT ); ?>" pattern="0?[0-9]|1[0-9]|2[0-3]"<?php echo $attributes; ?>>
						<span aria-hidden="true"><?php _ex( 'h', 'hour', 'secupress' ); ?></span>
					</label>
					<label>
						<span class="screen-reader-text"><?php _e( 'Minute' ); ?></span>
						<input id="<?php echo $args['name']; ?>_to_minute" name="<?php echo $name_attribute; ?>[to_minute]" value="<?php echo str_pad( $to_minute, 2, 0, STR_PAD_LEFT ); ?>" pattern="0?[0-9]|[1-5][0-9]"<?php echo $attributes; ?>>
						<span aria-hidden="true"><?php _ex( 'min', 'minute', 'secupress' ); ?></span>
					</label>
				</fieldset>
				<?php
				break;

			case 'html' :

				echo $value;
				break;

			case 'submit' :

				echo '<button type="submit" class="secupress-button" id="' . esc_attr( $args['name'] ) . '">' . $args['label'] . '</button>';
				break;

			default :
				if ( secupress_is_pro() && function_exists( 'secupress_pro_' . $args['type'] . '_field' ) ) {
					call_user_func( 'secupress_pro_' . $args['type'] . '_field', $args, $this );
				} elseif ( method_exists( $this, $args['type'] ) ) {
					call_user_func( array( $this, $args['type'] ), $args );
				} else {
					echo 'Missing or incorrect type'; // Do not translate.
				}
		}

		// Helpers.
		static::helpers( $args );

		if ( $has_fieldset_end ) {
			echo '</fieldset>';
		}
	}


	/**
	 * Used to display buttons.
	 *
	 * @since 1.0
	 *
	 * @param (array) $args An array of parameters. See `::field()`.
	 */
	protected function field_button( $args ) {

		if ( ! empty( $args['label'] ) ) {
			$class  = sanitize_html_class( $args['name'] );
			$class .= ! empty( $args['style'] ) ? ' button-' . sanitize_html_class( $args['style'] ) : ' button-secondary';
			$id     = ! empty( $args['id'] )    ? ' id="' . $args['id'] . '"' : '';

			if ( ! empty( $args['url'] ) ) {
				echo '<a' . $id . ' class="secupress-button secupress-button-primary secupressicon-'. $class . ( ! empty( $args['disabled'] ) ? ' disabled' : '' ) . '" href="' . esc_url( $args['url'] ) . '">' . $args['label'] . '</a>';
			}
			else {
				echo '<button' . $id . ' class="secupress-button secupress-button-primary secupressicon-' . $class . '"' . ( ! empty( $args['disabled'] ) ? ' disabled="disabled"' : '' ) . ' type="button">' . $args['label'] . '</button>';
			}
		}

		// Helpers.
		static::helpers( $args );
	}


	/**
	 * Helpers printed after a field.
	 *
	 * @since 1.0
	 *
	 * @param (array) $args An array containing a 'helpers' key.
	 *                      This 'helpers' key contains a list of arrays that contain:
	 *                      - (string) $description The text to print.
	 *                      - (string) $type        The helper type: 'description', 'help', 'warning'.
	 *                      - (string) $class       A html class to add to the text.
	 *                      - (string) $depends     Like in `$this->do_settings_fields()`, used to show/hide the helper depending on a field value.
	 */
	protected static function helpers( $args ) {
		if ( empty( $args['helpers'] ) || ! is_array( $args['helpers'] ) ) {
			return;
		}

		foreach ( $args['helpers'] as $helper ) {

			if ( empty( $helper['description'] ) ) {
				continue;
			}

			$depends = '';
			if ( ! empty( $helper['depends'] ) ) {
				$helper['depends'] = explode( ' ', $helper['depends'] );
				$depends           = ' depends-' . implode( ' depends-', $helper['depends'] );
			}

			$class = ! empty( $helper['class'] ) ? ' ' . trim( $helper['class'] ) : '';
			$name  = $args['name'];
			$type  = $helper['type'];

			switch ( $type ) {
				case 'description' :
					$description = '<p class="description desc' . $depends . $class . '">' . $helper['description'] . '</p>';
					break;
				case 'help' :
					$description = '<p class="description help' . $depends . $class . '">' . $helper['description'] . '</p>';
					break;
				case 'warning' :
					$description = '<p class="description warning' . $depends . $class . '"><strong>' . __( 'Warning: ', 'secupress' ) . '</strong>' . $helper['description'] . '</p>';
					break;
				default :
					continue;
			}

			/**
			 * Filter the helper description.
			 *
			 * @since 1.0
			 *
			 * @param (string) $description The description.
			 * @param (string) $name        The field name argument.
			 * @param (string) $type        The helper type.
			 */
			echo apply_filters( 'secupress.settings.help', $description, $name, $type );
		}
	}


	// Specific fields =============================================================================.

	/**
	 * Outputs the form used by the importers to accept the data to be imported.
	 *
	 * @since 1.0
	 */
	protected function import_upload_form() {
		/** This filter is documented in wp-admin/includes/template.php */
		$bytes      = apply_filters( 'import_upload_size_limit', wp_max_upload_size() );
		$size       = size_format( $bytes );
		$upload_dir = wp_upload_dir();
		$disabled   = secupress_is_pro() ? '' : ' disabled="disabled"';

		if ( ! empty( $upload_dir['error'] ) ) {
			?>
			<div class="error">
				<p><?php _e( 'Before you can upload your import file, you will need to fix the following error:', 'secupress' ); ?></p>
				<p><strong><?php echo $upload_dir['error']; ?></strong></p>
			</div><?php
			return;
		}

		$name        = 'upload';
		$type        = 'help';
		$description = __( 'Choose a file from your computer:', 'secupress' ) . ' (' . sprintf( __( 'Maximum size: %s', 'secupress' ), $size ) . ')';
		/** This filter is documented in inc/classes/settings/class-secupress-settings.php */
		$description = apply_filters( 'secupress.settings.help', $description, $name, $type );
		?>
		<p>
			<input type="file" id="upload" name="import" size="25"<?php echo $disabled; ?>/><br/>
			<label for="upload"><?php echo $description; ?></label>
			<input type="hidden" name="max_file_size" value="<?php echo $bytes; ?>" />
		</p>

		<p class="submit">
			<button type="submit"<?php echo $disabled; ?> class="secupress-button secupress-button-mini" id="import">
				<span class="icon">
					<i class="icon-upload" aria-hidden="true"></i>
				</span>
				<span class="text">
					<?php esc_html_e( 'Upload file and import settings', 'secupress' ); ?>
				</span>
			</button>
		</p>
		<?php
	}


	/**
	 * Outputs the export button.
	 *
	 * @since 1.0
	 */
	protected function export_form() {
		if ( secupress_is_pro() ) {
			?>
			<a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=secupress_export' ), 'secupress_export' ) ); ?>" id="export" class="secupress-button secupress-button-mini secupressicon">
				<span class="icon">
					<i class="icon-download" aria-hidden="true"></i>
				</span>
				<span class="text">
					<?php _e( 'Download settings', 'secupress' ); ?>
				</span>
			</a>
			<?php
		} else {
			?>
			<button class="secupress-button secupress-button-mini" disabled="disabled">
				<span class="icon">
					<i class="icon-download" aria-hidden="true"></i>
				</span>
				<span class="text">
					<?php _e( 'Download settings', 'secupress' ); ?>
				</span>
			</button>
			<?php
		}
	}


	/**
	 * Displays the scheduled backups module
	 *
	 * @since 1.0
	 */
	protected function scheduled_backups() {
		// //// Tempo.
		echo '<p><em>No scheduled backups yet, create one?</em></p>';
		echo '<a href="' . esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=secupress_clear_alerts' ), 'secupress_clear_alerts' ) ) . '" class="secupress-button">' . __( 'Clear Alerts', 'secupress' ) . '</a>';
	}


	/**
	 * Displays the banned IPs and add actions to delete them or add new ones.
	 *
	 * @since 1.0
	 */
	protected function banned_ips() {
		$ban_ips            = get_site_option( SECUPRESS_BAN_IP );
		$ban_ips            = is_array( $ban_ips ) ? $ban_ips : array();
		$offset             = get_option( 'gmt_offset' ) * HOUR_IN_SECONDS;
		$in_ten_years       = time() + YEAR_IN_SECONDS * 10;
		$page_url           = secupress_admin_url( 'modules', 'logs' );
		$referer_arg        = '&_wp_http_referer=' . urlencode( esc_url_raw( $page_url ) );
		$is_search          = false;
		$search_val         = '';
		$empty_list_message = __( 'No Banned IPs yet.', 'secupress' );

		// Ban form.
		echo '<form id="form-ban-ip" class="hide-if-js" action="' . esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=secupress-ban-ip' . $referer_arg ), 'secupress-ban-ip' ) ) . '" method="post">';
			echo '<label for="secupress-ban-ip" class="screen-reader-text">' . __( 'Specify an IP to ban.', 'secupress' ) . '</label><br/>';
			echo '<input type="text" id="secupress-ban-ip" name="ip" value=""/> ';
			echo '<button type="submit" class="secupress-button secupress-button-mini">' . __( 'Ban IP', 'secupress' ) . '</button>';
		echo "</form>\n";

		// Search.
		if ( $ban_ips && ! empty( $_POST['secupress-search-banned-ip'] ) ) { // WPCS: CSRF ok.
			$search    = urldecode( trim( $_POST['secupress-search-banned-ip'] ) ); // WPCS: CSRF ok.
			$is_search = true;

			if ( secupress_ip_is_valid( $search ) ) {
				$search_val = esc_attr( $search );

				if ( isset( $ban_ips[ $search ] ) ) {
					$ban_ips = array(
						$search => $ban_ips[ $search ],
					);
				} else {
					$ban_ips            = array();
					$empty_list_message = __( 'IP not found.', 'secupress' );
				}
			} else {
				$ban_ips            = array();
				$empty_list_message = __( 'Not a valid IP.', 'secupress' );
			}
		}

		// Search form.
		echo '<form id="form-search-ip"' . ( $ban_ips || $is_search ? '' : ' class="hidden"' ) . ' method="post">';
			echo '<label for="secupress-search-banned-ip" class="screen-reader-text">' . __( 'Search IP', 'secupress' ) . '</label><br/>';
			echo '<input type="search" id="secupress-search-banned-ip" name="secupress-search-banned-ip" value="' . $search_val . '"/> ';
			echo '<button type="submit" class="button button-primary" data-loading-i18n="' . esc_attr__( 'Searching...', 'secupress' ) . '" data-original-i18n="' . esc_attr__( 'Search IP', 'secupress' ) . '">' . __( 'Search IP', 'secupress' ) . '</button> ';
			echo '<span class="spinner secupress-inline-spinner hide-if-no-js"></span>';
			echo '<a class="button button-secondary' . ( $search_val ? '' : ' hidden' ) . '" id="reset-banned-ips-list" href="' . esc_url( $page_url ) . '" data-loading-i18n="' . esc_attr__( 'Reseting...', 'secupress' ) . '" data-original-i18n="' . esc_attr__( 'Reset', 'secupress' ) . '">' . __( 'Reset', 'secupress' ) . '</a> ';
			echo '<span class="spinner secupress-inline-spinner' . ( $search_val ? ' hide-if-no-js' : ' hidden' ) . '"></span>';
		echo "</form>\n";

		// Slice the list a bit: limit to 100 last results.
		if ( count( $ban_ips ) > 100 ) {
			$ban_ips = array_slice( $ban_ips, -100 );
			/* translators: %d is 100 */
			echo '<p>' . sprintf( __( 'Last %d banned IPs:', 'secupress' ), 100 ) . "</p>\n";
		}

		// Display the list.
		echo '<ul id="secupress-banned-ips-list" class="secupress-boxed-group">';
		if ( $ban_ips ) {
			foreach ( $ban_ips as $ip => $time ) {
				echo '<li class="secupress-large-row">';
					$format = __( 'M jS Y', 'secupress' ) . ' ' . __( 'G:i', 'secupress' );
					$time   = $time > $in_ten_years ? __( 'Forever', 'secupress' ) : date_i18n( $format, $time + $offset );
					$href   = wp_nonce_url( admin_url( 'admin-post.php?action=secupress-unban-ip&ip=' . esc_attr( $ip ) . $referer_arg ), 'secupress-unban-ip_' . $ip );

					printf( '<strong>%s</strong> <em>(%s)</em>', esc_html( $ip ), $time );
					printf( '<span><a class="a-unban-ip" href="%s">%s</a> <span class="spinner secupress-inline-spinner hide-if-no-js"></span></span>', esc_url( $href ), __( 'Delete', 'secupress' ) );
				echo "</li>\n";
			}
		} else {
			echo '<li id="no-ips">' . $empty_list_message . '</li>';
		}
		echo "</ul>\n";

		// Actions.
		echo '<p id="secupress-banned-ips-actions">';
			// Display a button to unban all IPs.
			$clear_href = wp_nonce_url( admin_url( 'admin-post.php?action=secupress-clear-ips' . $referer_arg ), 'secupress-clear-ips' );
			echo '<a class="secupress-button secupress-button-secondary' . ( $ban_ips || $is_search ? '' : ' hidden' ) . '" id="secupress-clear-ips-button" href="' . esc_url( $clear_href ) . '" data-loading-i18n="' . esc_attr__( 'Clearing...', 'secupress' ) . '" data-original-i18n="' . esc_attr__( 'Clear all IPs', 'secupress' ) . '">' . __( 'Clear all IPs', 'secupress' ) . "</a>\n";
			echo '<span class="spinner secupress-inline-spinner' . ( $ban_ips || $is_search ? ' hide-if-no-js' : ' hidden' ) . '"></span>';
			// For JS: ban a IP.
			echo '<button type="button" class="secupress-button secupress-button-primary hide-if-no-js" id="secupress-ban-ip-button" data-loading-i18n="' . esc_attr__( 'Banishing...', 'secupress' ) . '" data-original-i18n="' . esc_attr__( 'Ban new IP', 'secupress' ) . '">' . __( 'Ban new IP', 'secupress' ) . "</button>\n";
			echo '<span class="spinner secupress-inline-spinner hide-if-no-js"></span>';
		echo "</p>\n";
	}


	/**
	 * Displays the textarea that lists the IP addresses not to ban.
	 *
	 * @since 1.0
	 *
	 * @param (array) $args An array of parameters. See `::field()`.
	 */
	protected function ips_whitelist( $args ) {
		$name_attribute = 'secupress_' . $this->modulenow . '_settings[' . $args['name'] . ']';
		$disabled       = ! empty( $args['disabled'] ) || static::is_pro_feature( $args['name'] );
		$disabled       = $disabled ? ' disabled="disabled"' : '';
		$attributes     = $disabled;
		$attributes    .= empty( $args['attributes']['cols'] ) ? ' cols="50"' : '';
		$attributes    .= empty( $args['attributes']['rows'] ) ? ' rows="5"'  : '';
		$whitelist      = secupress_get_module_option( $args['name'] );

		if ( $whitelist ) {
			$whitelist = explode( "\n", $whitelist );
			$whitelist = array_map( 'secupress_ip_is_valid', $whitelist );
			$whitelist = array_filter( $whitelist );
			natsort( $whitelist );
			$whitelist = implode( "\n", $whitelist );
		} else {
			$whitelist = '';
		}

		// Labels.
		$label_open  = '';
		$label_close = '';
		if ( '' !== $args['label_before'] || '' !== $args['label'] || '' !== $args['label_after'] ) {
			$label_open  = '<label' . ( $disabled ? ' class="disabled"' : '' ) . '>';
			$label_close = '</label>';
		}

		$this->print_open_form_tag();

			echo $label_open;
				echo $args['label'] ? $args['label'] . '<br/>' : '';
				echo $args['label_before'];
				echo '<textarea id="' . $args['label_for'] . '" name="' . $name_attribute . '"' . $attributes . '>' . esc_textarea( $whitelist ) . "</textarea>\n";
				echo $args['label_after'];
			echo $label_close;

			echo '<p class="description">' . __( 'One IP address per line.', 'secupress' ) . "</p>\n";

			echo '<p class="submit"><button type="submit" class="secupress-button secupress-button-primary"' . $disabled . '> ' . __( 'Save whitelist', 'secupress' ) . '</button></p>';

		$this->print_close_form_tag();
	}


	/**
	 * Displays the checkbox to activate the "action" Logs.
	 *
	 * @since 1.0
	 *
	 * @param (array) $args An array of parameters. See `::field()`.
	 */
	protected function activate_action_logs( $args ) {
		$name_attribute = 'secupress-plugin-activation[' . $args['name'] . ']';
		$disabled       = ! empty( $args['disabled'] ) || static::is_pro_feature( $args['name'] );
		$disabled       = $disabled ? ' disabled="disabled"' : '';
		$value          = (int) secupress_is_submodule_active( 'logs', 'action-logs' );

		// Labels.
		$label_open  = '';
		$label_close = '';
		if ( '' !== $args['label_before'] || '' !== $args['label'] || '' !== $args['label_after'] ) {
			$label_open  = '<label' . ( $disabled ? ' class="disabled"' : '' ) . '>';
			$label_close = '</label>';
		}
		?>
		<form action="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=secupress_activate_action_logs' ), 'secupress_activate_action_logs' ) ); ?>" id="form-activate-action-logs" method="post">
			<p><?php echo $label_open; ?>
				<?php
				echo $args['label_before'];
				echo ' <input type="checkbox" id="' . $args['label_for'] . '" name="' . $name_attribute . '" value="1"' . checked( $value, 1, false ) .  $disabled . ' class="secupress-checkbox" /> ';
				echo '<span class="label-text">' . $args['label'] . '</span>';
				?>
			<?php echo $label_close; ?>
			</p>
			<?php

			echo '<p class="description desc">';
				_e( 'We will not log post action like creation or update but rather password and profile update, email changes, new administrator user, admin has logged in...', 'secupress' );
			echo "</p>\n";

			echo '<p class="submit"><button type="submit" class="secupress-button secupress-button-primary">' . esc_html__( 'Submit' ) . '</button></p>';
			?>
		</form>
		<?php
	}


	/**
	 * Displays the checkbox to activate the "404" Logs.
	 *
	 * @since 1.0
	 *
	 * @param (array) $args An array of parameters. See `::field()`.
	 */
	protected function activate_404_logs( $args ) {
		$name_attribute = 'secupress-plugin-activation[' . $args['name'] . ']';
		$disabled       = ! empty( $args['disabled'] ) || static::is_pro_feature( $args['name'] );
		$disabled       = $disabled ? ' disabled="disabled"' : '';
		$value          = (int) secupress_is_submodule_active( 'logs', '404-logs' );

		// Labels.
		$label_open  = '';
		$label_close = '';
		if ( '' !== $args['label_before'] || '' !== $args['label'] || '' !== $args['label_after'] ) {
			$label_open  = '<label' . ( $disabled ? ' class="disabled"' : '' ) . '>';
			$label_close = '</label>';
		}
		?>
		<form action="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=secupress_activate_404_logs' ), 'secupress_activate_404_logs' ) ); ?>" id="form-activate-404-logs" method="post">
			<p><?php echo $label_open; ?>
				<?php
				echo $args['label_before'];
				echo ' <input type="checkbox" id="' . $args['label_for'] . '" name="' . $name_attribute . '" value="1"' . checked( $value, 1, false ) .  $disabled . 'class="secupress-checkbox" /> ';
				echo '<span class="label-text">' . $args['label'] . '</span>';
				?>
			<?php echo $label_close; ?>
			</p>
			<?php echo '<p class="submit"><button type="submit" class="secupress-button secupress-button-primary">' . esc_html__( 'Submit' ) . '</button></p>'; ?>
		</form>
		<?php
	}


	/**
	 * Displays the old backups.
	 *
	 * @since 1.0
	 */
	protected function backup_history() {
		$backup_files = secupress_get_backup_file_list();
		?>
		<p id="secupress-no-backups"<?php echo $backup_files ? ' class="hidden"' : ''; ?>><em><?php _e( 'No Backups found yet, do one?', 'secupress' ); ?></em></p>

		<form id="form-delete-backups"<?php echo ! $backup_files ? ' class="hidden"' : ''; ?> action="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=secupress_delete_backups' ), 'secupress_delete_backups' ) ); ?>" method="post">

			<strong id="secupress-available-backups"><?php printf( _n( '%s available Backup', '%s available Backups', count( $backup_files ), 'secupress' ), number_format_i18n( count( $backup_files ) ) ); ?></strong>

			<fieldset class="secupress-boxed-group">
				<legend class="screen-reader-text"><span><?php esc_html_e( 'Backups', 'secupress' ); ?></span></legend>
				<?php array_map( 'secupress_print_backup_file_formated', array_reverse( $backup_files ) ); ?>
			</fieldset>

			<p class="submit">
				<button class="secupress-button secupress-button-secondary alignright" type="submit" id="submit-delete-backups">
					<span class="icon">
						<i class="icon-cross"></i>
					</span>
					<span class="text">
						<?php esc_html_e( 'Delete all Backups', 'secupress' ); ?>
					</span>
				</button>
			</p>

		</form>
		<?php
	}


	/**
	 * Displays the tables to launch a backup
	 *
	 * @since 1.0
	 */
	protected function backup_db() {
		$wp_tables    = secupress_get_wp_tables();
		$other_tables = secupress_get_non_wp_tables();
		?>
		<form action="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=secupress_backup_db' ), 'secupress_backup_db' ) ); ?>" id="form-do-db-backup" method="post">

			<fieldset class="secupress-boxed-group">
				<legend class="screen-reader-text"><span><?php esc_html_e( 'DataBase Tables', 'secupress' ); ?></span></legend>

				<b><?php _e( 'Unknown tables', 'secupress' ); ?></b>
				<br>
				<?php
				foreach ( $other_tables as $table ) {
					echo '<label><input checked="checked" name="other_tables[]" type="checkbox" class="secupress-checkbox secupress-checkbox-mini"> <span class="label-text">' . $table . '</span></label><br>';
				}
				?>
				<hr>
				<b><?php _e( 'WordPress tables (mandatory)', 'secupress' ); ?></b>
				<br>
				<?php
				foreach ( $wp_tables as $table ) {
					echo '<label><input disabled="disabled" checked="checked" type="checkbox" class="secupress-checkbox secupress-checkbox-mini"> <span class="label-text">' . $table . '</span></label><br>';
				}
				?>
			</fieldset>

			<p class="submit">
				<button class="secupress-button secupress-button-primary alignright" type="submit" data-original-i18n="<?php esc_attr_e( 'Backup my Database', 'secupress' ); ?>" data-loading-i18n="<?php esc_attr_e( 'Backuping&hellip;', 'secupress' ); ?>" id="submit-backup-db">
					<span class="icon">
						<i class="icon-download"></i>
					</span>
					<span class="text">
						<?php esc_html_e( 'Backup my Database', 'secupress' ); ?>
					</span>
				</button>
				<span class="spinner secupress-inline-spinner"></span>
			</p>

		</form>
		<?php
	}


	/**
	 * Displays the files backups and the button to launch one.
	 *
	 * @since 1.0
	 */
	protected function backup_files() {
		$disabled            = disabled( ! secupress_is_pro(), true, false );
		$ignored_directories = get_site_option( 'secupress_file-backups_settings' );
		$ignored_directories = ! empty( $ignored_directories['ignored_directories'] ) ? $ignored_directories['ignored_directories'] : '';
		?>
		<form action="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=secupress_backup_files' ), 'secupress_backup_files' ) ); ?>" id="form-do-files-backup" method="post">

			<fieldset>
				<legend><strong><label for="ignored_directories"><?php _e( 'Do not backup the following files and folders:', 'secupress' ); ?></label></strong></legend>
				<br>
				<textarea id="ignored_directories" name="ignored_directories" cols="50" rows="5"<?php echo $disabled; ?>><?php echo esc_textarea( $ignored_directories ); ?></textarea>
				<p class="description">
					<?php _e( 'One file or folder per line.', 'secupress' ); ?>
				</p>
			</fieldset>

			<p class="submit">
				<button class="secupress-button secupress-button-primary alignright" type="submit" data-original-i18n="<?php esc_attr_e( 'Backup my Files', 'secupress' ); ?>" data-loading-i18n="<?php esc_attr_e( 'Backuping&hellip;', 'secupress' ); ?>" id="submit-backup-files"<?php echo $disabled; ?>>
					<span class="icon">
						<i class="icon-download"></i>
					</span>
					<span class="text">
						<?php esc_html_e( 'Backup my Files', 'secupress' ); ?>
					</span>
				</button>
				<span class="spinner secupress-inline-spinner"></span>
			</p>

		</form>
		<?php
	}


	/**
	 * Scan the installation and search for modified/malicious files
	 *
	 * @since 1.0
	 */
	protected function file_scanner() {
		if ( ! secupress_is_pro() ) {
			?>
			<button class="secupress-button disabled" type="button">
				<?php esc_html_e( 'Search for malicious files', 'secupress' ); ?>
			</button>
			<?php
		} else {
			/**
			 * Fires when SecuPress Pro loads this field.
			 *
			 * @since 1.0
			 */
	 		do_action( 'secupress.settings.field.file_scanner' );
		}
	}


	// Fields related ==============================================================================.

	/**
	 * Get a correct name for setting fields based on the current module.
	 *
	 * @since 1.0
	 *
	 * @param (string) $field A field name.
	 *
	 * @return (string)
	 */
	final protected function get_field_name( $field ) {
		return "{$this->pluginnow}_{$field}";
	}


	/**
	 * Add a field. It's a wrapper for `add_settings_field()`.
	 *
	 * @since 1.0
	 *
	 * @param (array) $args An array of parameters:
	 *                - (string) $title       The row title/label.
	 *                - (string) $description The row description.
	 *                - (string) $field_type  The field type.
	 *                See `self::field()` for the other paramaters.
	 *
	 * @return (object) The class instance.
	 */
	protected function add_field( $args ) {

		$args = wp_parse_args( $args, array(
			'title'       => '',
			'description' => '',
			'name'        => '',
			'field_type'  => 'field',
		) );

		if ( empty( $args['name'] ) && ! empty( $args['label_for'] ) ) {
			$args['name'] = $args['label_for'];
		}

		// Get the title.
		$title = $args['title'];
		unset( $args['title'] );

		// Get the callback.
		if ( is_array( $args['field_type'] ) ) {
			$callback = $args['field_type'];
		} elseif ( method_exists( $this, $args['field_type'] ) ) {
			$callback = array( $this, $args['field_type'] );
		} else {
			$callback = 'secupress_' . $args['field_type'];
		}

		add_settings_field(
			'module_' . $this->modulenow . '|' . $this->pluginnow . '|' . $args['name'],
			$title,
			$callback,
			$this->get_section_id(),
			$this->get_section_id(),
			$args
		);

		/**
		 * Triggered after a field is added.
		 *
		 * @since 1.0
		 */
		do_action( 'secupress.settings.after_field_' . $this->modulenow . '|' . $this->pluginnow );

		return $this;
	}


	/**
	 * Like the `do_settings_fields()` WordPress function but:
	 * - `id` and `class` attributes can be added to the `tr` tag (the `class` attribute appeared in WP 4.3) with `row_id` and `row_class`.
	 * - The `$depends` parameter can be used to show/hide the row depending on a field value.
	 * - Automatically add some text to the row description if the field is pro and w're not using the pro version.
	 *
	 * @since 1.0
	 *
	 * @param (string) $page    Slug title of the admin page who's settings fields you want to show.
	 * @param (string) $section Slug title of the settings section who's fields you want to show.
	 */
	final protected static function do_settings_fields( $page, $section ) {
		global $wp_settings_fields;

		if ( ! isset( $wp_settings_fields[ $page ][ $section ] ) ) {
			return;
		}

		foreach ( (array) $wp_settings_fields[ $page ][ $section ] as $field ) {
			$id       = '';
			$field_id = isset( $field['id'] ) ? explode( '|', $field['id'] ) : array( '' );
			$field_id = end( $field_id );
			$is_pro   = static::is_pro_feature( $field['args']['name'] );
			$class    = 'secupress-setting-row ' . ( $is_pro ? 'secupress-pro-row ' : '' ) . 'secupress-setting-row_' . sanitize_html_class( $field_id ) . ' ';

			// Row ID.
			if ( ! empty( $field['args']['row_id'] ) ) {
				$id = ' id="' . esc_attr( $field['args']['row_id'] ) . '"';
			}

			// Row class.
			if ( ! empty( $field['args']['row_class'] ) ) {
				$class .= $field['args']['row_class'];
			}

			if ( ! empty( $field['args']['depends'] ) ) {
				$field['args']['depends'] = explode( ' ', $field['args']['depends'] );
				$class .= ' depends-' . implode( ' depends-', $field['args']['depends'] );
			}

			if ( $class ) {
				$class = ' class="' . esc_attr( trim( $class ) ) . '"';
			}

			unset( $field['args']['row_id'], $field['args']['row_class'], $field['args']['depends'] );
			?>
			<div<?php echo $id . $class; ?>>
				<div class="secupress-flex">
					<div class="secupress-setting-content-col">
					<?php
					// Row title.
					if ( $field['title'] ) {

						if ( ! empty( $field['args']['label_for'] ) ) {
							echo '<h4 id="row-' . sanitize_html_class( $field_id ) . '" class="screen-reader-text">' . $field['title'] . '</h4>';
							echo '<label for="' . esc_attr( $field['args']['label_for'] ) . '" class="secupress-setting-row-title">' . $field['title'] . '</label>';
						} else {
							echo '<h4 id="row-' . sanitize_html_class( $field_id ) . '" class="secupress-setting-row-title">' . $field['title'] . '</h4>';
						}
					}

					if ( $field['args']['description'] ) {
						echo '<p class="description">' . $field['args']['description'] . '</p>';
					}
					unset( $field['args']['description'] );

					call_user_func( $field['callback'], $field['args'] );
					?>
					</div>
					<div class="secupress-get-pro-col">
					<?php
					if ( $is_pro ) {
						echo '<p class="secupress-get-pro">' . static::get_pro_version_string() . '</p>';
					}
					?>
					</div><!-- .secupress-get-pro-col -->
				</div><!-- .secupress-flex -->
			</div>
			<?php
		}
	}


	// Main template tags ==========================================================================.

	/**
	 * Print the page content. Must be extended.
	 *
	 * @since 1.0
	 */
	public function print_page() {
		die( 'Method SecuPress_Settings::print_page() must be over-ridden in a sub-class.' );
	}


	// Other template tags =========================================================================.

	/**
	 * Print the current section description (because you wouldn't guess by the method's name, be thankful).
	 *
	 * @since 1.0
	 *
	 * @return (object) The class instance.
	 */
	protected function print_section_description() {
		$key = $this->modulenow . '|' . $this->sectionnow;

		if ( ! empty( $this->section_descriptions[ $key ] ) ) {
			echo '<div class="secupress-settings-section-description">';
				echo $this->section_descriptions[ $key ];
			echo '</div>';
		}

		return $this;
	}


	/**
	 * Get or print a submit button.
	 *
	 * @since 1.0
	 *
	 * @param (string)       $type             Optional. The type of button. Accepts 'primary', 'secondary', or 'delete'. Default 'primary large'.
	 * @param (string)       $name             Optional. The HTML name of the submit button. If no id attribute is given in $other_attributes below, `$name` will be used as the button's id. Default 'main_submit'.
	 * @param (bool|string)  $wrap             Optional. True if the output button should be wrapped in a paragraph tag, false otherwise. Can be used as a string to add a class to the wrapper. Default true.
	 * @param (array|string) $other_attributes Optional. Other attributes that should be output with the button, mapping attributes to their values, such as `array( 'tabindex' => '1' )`. These attributes will be output as `attribute="value"`, such as `tabindex="1"`. Other attributes can also be provided as a string such as `tabindex="1"`, though the array format is typically cleaner. Default empty.
	 * @param (bool)         $echo             Optional. True if the button should be "echo"ed, false otherwise.
	 *
	 * @return (string) Submit button HTML.
	 */
	protected static function submit_button( $type = 'primary large', $name = 'main_submit', $wrap = true, $other_attributes = null, $echo = true ) {
		if ( true === $wrap ) {
			$wrap = '<p class="submit">';
		} elseif ( $wrap ) {
			$wrap = '<p class="submit ' . sanitize_html_class( $wrap ) . '">';
		}

		if ( ! is_array( $type ) ) {
			$type = explode( ' ', $type );
		}

		$button_shorthand = array( 'primary' => 1, 'secondary' => 1, 'tertiary' => 1, 'small' => 1, 'large' => 1, 'delete' => 1 );
		$classes          = array( 'secupress-button' );

		foreach ( $type as $t ) {
			$classes[] = isset( $button_shorthand[ $t ] ) ? 'secupress-button-' . $t : $t;
		}
		$class = implode( ' ', array_unique( $classes ) );

		// Default the id attribute to $name unless an id was specifically provided in $other_attributes.
		$id = $name;
		if ( is_array( $other_attributes ) && isset( $other_attributes['id'] ) ) {
			$id = $other_attributes['id'];
			unset( $other_attributes['id'] );
		}

		$attributes = '';
		if ( is_array( $other_attributes ) ) {
			foreach ( $other_attributes as $attribute => $value ) {
				$attributes .= ' ' . $attribute . '="' . esc_attr( $value ) . '"';
			}
		} elseif ( ! empty( $other_attributes ) ) { // Attributes provided as a string.
			$attributes = $other_attributes;
		}

		// Don't output empty name and id attributes.
		$name_attr = $name ? ' name="' . esc_attr( $name ) . '"' : '';
		$id_attr   = $id   ? ' id="' . esc_attr( $id ) . '"'     : '';

		$button = '<button type="submit"' . $name_attr . $id_attr . ' class="' . esc_attr( $class ) . '"' . $attributes . '/>' . __( 'Save All Changes', 'secupress' ) . '</button>';

		if ( $wrap ) {
			$button = $wrap . $button . '</p>';
		}

		if ( $echo ) {
			echo $button;
		}

		return $button;
	}


	// Utilities ===================================================================================.

	/**
	 * Tell if the option value is for the pro version and we're not using the pro version.
	 *
	 * @since 1.0
	 *
	 * @param (string) $value The option value.
	 *
	 * @return (bool) True if the option value is for pro version but w're not using the pro version.
	 */
	protected static function is_pro_feature( $value ) {
		return secupress_feature_is_pro( $value ) && ! secupress_is_pro();
	}


	/**
	 * Returns a i18n message to act like a CTA on pro version.
	 *
	 * @since 1.0
	 *
	 * @param (string) $format You can use it to embed the message in a HTML tag, usage of "%s" is mandatory.
	 *
	 * @return (string)
	 */
	protected static function get_pro_version_string( $format = '' ) {
		$message = sprintf( __( 'Available in <a href="%s">Pro Version</a>.', 'secupress' ), '#' ); // //// #.
		if ( $format ) {
			$message = sprintf( $format, $message );
		}
		return $message;
	}


	// Includes ====================================================================================.

	/**
	 * Include a module settings file. Also, automatically set the current module and print the sections.
	 *
	 * @since 1.0
	 *
	 * @param (string) $module_file Absolute path to the module settings file.
	 * @param (string) $module      The module.
	 *
	 * @return (object) The class instance.
	 */
	final protected function require_settings_file( $module_file, $module ) {

		if ( file_exists( $module_file ) ) {
			$this->set_current_plugin( $module );

			require( $module_file );

			$this->do_sections();
		}

		return $this;
	}
}
