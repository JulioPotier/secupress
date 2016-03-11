<?php
defined( 'ABSPATH' ) or die('Cheatin\' uh?');


/**
 * Base class for settings.
 *
 * @package SecuPress
 * @since 1.0
 */

abstract class SecuPress_Settings extends SecuPress_Singleton {

	const VERSION = '1.0';

	protected $modulenow;  // Tab (page), like `users_login`.
	protected $sectionnow; // Section, like `login_auth`.
	protected $pluginnow;  // Field, like `double_auth`.
	protected $sections_descriptions = array();
	protected $sections_save_button  = array();
	protected $form_action;
	protected $with_form = true;


	// Setters =====================================================================================

	protected function set_current_module() {
		die( 'Method SecuPress_Settings::set_current_module() must be over-ridden in a sub-class.' );
	}


	final protected function set_current_section( $section ) {
		$this->sectionnow = $section;
		return $this;
	}


	final protected function set_current_plugin( $plugin ) {
		$this->pluginnow = $plugin;
		return $this;
	}


	final protected function set_section_description( $description ) {
		$section_id = $this->modulenow . '|' . $this->sectionnow;

		$this->sections_descriptions[ $section_id ] = $description;

		return $this;
	}


	final protected function set_section_save_button( $value ) {
		$section_id = $this->get_section_id();

		if ( $value ) {
			$this->sections_save_button[ $section_id ] = 1;
		} else {
			unset( $this->sections_save_button[ $section_id ] );
		}

		return $this;
	}


	// Getters =====================================================================================

	final public function get_current_module() {
		return $this->modulenow;
	}


	final public function get_current_section() {
		return $this->sectionnow;
	}


	final public function get_current_plugin() {
		return $this->pluginnow;
	}


	public function get_section_id() {
		return 'module_' . $this->modulenow . '|' . $this->sectionnow;
	}


	final public function get_form_action() {
		return $this->form_action;
	}


	final public function get_with_form() {
		return $this->with_form;
	}


	// Init ========================================================================================

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


	// Sections ====================================================================================

	/**
	 * Add a new block in the page.
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

		do_action( 'before_section_' . $this->sectionnow, (bool) $args['with_save_button'] );

		add_settings_section(
			$section_id,
			$title . $actions,
			array( $this, 'print_section_description' ),
			$section_id
		);

		if ( (bool) $args['with_save_button'] ) {
			$this->sections_save_button[ $section_id ] = 1;
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
			'default'      => array(), //// (TODO) not supported yet why not $args['with_roles']
			'label_screen' => __( 'Affected Roles', 'secupress' ),
			'helpers'      => array(
				array(
					'type'        => 'description',
					'description' => __( 'Future roles will be automatically checked.', 'secupress' )
				),
				array(
					'type'        => 'warning',
					'class'       => 'hide-if-js',
					'description' => __( 'Select 1 role minimum', 'secupress' )
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

		$section_id = $this->get_section_id();

		echo '<div class="secublock">';
			$this->do_settings_sections();
		echo '</div>';

		$with_save_button = ! empty( $this->sections_save_button[ $section_id ] );
		if ( $with_save_button ) {
			static::submit_button( 'primary small', $this->sectionnow . '_submit' );
		}
		do_action( 'after_section_' . $this->sectionnow, $with_save_button );

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
			if ( $section['title'] ) {
				echo '<h3 id="' . sanitize_key( $section['title'] ) . '">' . $section['title'] . '</h3>' . "\n";
			}

			if ( $section['callback'] ) {
				call_user_func( $section['callback'], $section );
			}

			if ( ! isset( $wp_settings_fields ) || ! isset( $wp_settings_fields[ $section_id ] ) || ! isset( $wp_settings_fields[ $section_id ][ $section['id'] ] ) ) {
				continue;
			}

			echo '<table class="form-table">';
				static::do_settings_fields( $section_id, $section['id'] );
			echo '</table>';
		}
	}


	// Generic fields ==============================================================================

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
	 *                - (bool)   $disabled          True to disable the field. Pro fields are autotically disabled on the free version.
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

		// Type
		$args['type'] = 'radio' === $args['type'] ? 'radios' : $args['type'];

		// Value
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

		// HTML attributes
		$attributes = '';
		$args['attributes']['class'] = ! empty( $args['attributes']['class'] ) ? (array) $args['attributes']['class'] : array();

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

		// Fieldset
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
				$fieldset_auto = array( 'checkboxes' => 1, 'radioboxes' => 1, 'radios' => 1, 'roles' => 1, );

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

		// Labels
		$label_open  = '';
		$label_close = '';
		if ( '' !== $args['label_before'] || '' !== $args['label'] || '' !== $args['label_after'] ) {
			$label_open  = '<label' . ( $disabled ? ' class="disabled"' : '' ) . '>';
			$label_close = '</label>';
		}

		// Types
		switch ( $args['type'] ) {
			case 'number' :
			case 'email' :
			case 'tel' :
			case 'text' :

				echo $label_open;
					echo $args['label'] ? $args['label'] . '<br/>' : '';
					echo $args['label_before'];
					?>
					<input type="<?php echo $args['type']; ?>" id="<?php echo $args['label_for']; ?>" name="<?php echo $name_attribute; ?>" value="<?php echo esc_attr( $value ); ?>"<?php echo $attributes; ?>/>
					<?php
					echo $args['label_after'];
				echo $label_close;
				break;

			case 'textarea' :

				$value       = esc_textarea( implode( "\n" , (array) $value ) );
				$attributes .= empty( $args['attributes']['cols'] ) ? ' cols="50"' : '';
				$attributes .= empty( $args['attributes']['rows'] ) ? ' rows="5"'  : '';

				echo $label_open;
					echo $args['label'] ? $args['label'] . '<br/>' : '';
					echo $args['label_before'];
					?>
					<textarea id="<?php echo $args['label_for']; ?>" name="<?php echo $name_attribute; ?>"<?php echo $attributes; ?>><?php echo $value; ?></textarea>
					<?php
					echo $args['label_after'];
				echo $label_close;
				break;

			case 'select' :

				$value = array_flip( (array) $value );
				$has_disabled = false;

				echo $label_open;
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
				echo $label_close;
				echo $has_disabled ? secupress_get_pro_version_string( '<span class="description">(*) %s</span>' ) : '';
				break;

			case 'checkbox' :

				echo $label_open;
					echo $args['label_before'];
					?>
					<input type="checkbox" id="<?php echo $args['label_for']; ?>" name="<?php echo $name_attribute; ?>" value="1"<?php checked( $value, 1 ); ?><?php echo $attributes; ?>/>
					<?php
					echo $args['label'];
				echo $label_close;
				break;

			case 'checkboxes' :
			case 'radioboxes' :

				$value = array_flip( (array) $value );

				foreach ( $args['options'] as $val => $title ) {
					$args['label_for'] = $args['name'] . '_' . $val;
					$disabled          = static::is_pro_feature( $args['name'] . '|' . $val ) ? ' disabled="disabled"' : '';
					?>
					<label<?php echo $disabled ? ' class="disabled"' : ''; ?>>
						<input type="checkbox" id="<?php echo $args['label_for']; ?>" name="<?php echo $name_attribute; ?>[]" value="<?php echo $val; ?>"<?php checked( isset( $value[ $val ] ) ); ?><?php echo $disabled; ?><?php echo $attributes; ?>>
						<?php echo $title; ?>
					</label>
					<?php echo static::is_pro_feature( $args['name'] . '|' . $val ) ? secupress_get_pro_version_string( '<span class="description">%s</span>' ) : ''; ?>
					<br/>
					<?php
				}
				break;

			case 'radios' : // Video killed the radio star.

				foreach ( $args['options'] as $val => $title ) {
					$args['label_for'] = $args['name'] . '_' . $val;
					$disabled          = static::is_pro_feature( $args['name'] . '|' . $val ) ? ' disabled="disabled"' : '';
					?>
					<label<?php echo $disabled ? ' class="disabled"' : ''; ?>>
						<input type="radio" id="<?php echo $args['label_for']; ?>" name="<?php echo $name_attribute; ?>" value="<?php echo $val; ?>"<?php checked( $value, $val ); ?><?php echo $disabled; ?><?php echo $attributes; ?>>
						<?php echo $title; ?>
					</label>
					<?php echo static::is_pro_feature( $args['name'] . '|' . $val ) ? secupress_get_pro_version_string( '<span class="description">%s</span>' ) : ''; ?>
					<br/>
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
					<label<?php echo $disabled ? ' class="disabled"' : ''; ?>>
						<input type="checkbox" name="<?php echo $name_attribute; ?>[]" value="<?php echo $val; ?>"<?php checked( ! isset( $value[ $val ] ) ); ?><?php echo $attributes; ?>>
						<?php echo $title; ?>
					</label>
					<br/>
					<?php
				}
				break;

			case 'countries' :
				$value = array_flip( (array) array_filter( $value ) );

				$_countries = array ( 'AF' => array ( 0 => 'Africa', 'AO' => 'Angola', 'BF' => 'Burkina Faso', 'BI' => 'Burundi', 'BJ' => 'Benin', 'BW' => 'Botswana', 'CD' => 'Congo, The Democratic Republic of the', 'CF' => 'Central African Republic', 'CG' => 'Congo', 'CI' => 'Cote D\'Ivoire', 'CM' => 'Cameroon', 'CV' => 'Cape Verde', 'DJ' => 'Djibouti', 'DZ' => 'Algeria', 'EG' => 'Egypt', 'EH' => 'Western Sahara', 'ER' => 'Eritrea', 'ET' => 'Ethiopia', 'GA' => 'Gabon', 'GH' => 'Ghana', 'GM' => 'Gambia', 'GN' => 'Guinea', 'GQ' => 'Equatorial Guinea', 'GW' => 'Guinea-Bissau', 'KE' => 'Kenya', 'KM' => 'Comoros', 'LR' => 'Liberia', 'LS' => 'Lesotho', 'LY' => 'Libya', 'MA' => 'Morocco', 'MG' => 'Madagascar', 'ML' => 'Mali', 'MR' => 'Mauritania', 'MU' => 'Mauritius', 'MW' => 'Malawi', 'MZ' => 'Mozambique', 'NA' => 'Namibia', 'NE' => 'Niger', 'NG' => 'Nigeria', 'RE' => 'Reunion', 'RW' => 'Rwanda', 'SC' => 'Seychelles', 'SD' => 'Sudan', 'SH' => 'Saint Helena', 'SL' => 'Sierra Leone', 'SN' => 'Senegal', 'SO' => 'Somalia', 'ST' => 'Sao Tome and Principe', 'SZ' => 'Swaziland', 'TD' => 'Chad', 'TG' => 'Togo', 'TN' => 'Tunisia', 'TZ' => 'Tanzania, United Republic of', 'UG' => 'Uganda', 'YT' => 'Mayotte', 'ZA' => 'South Africa', 'ZM' => 'Zambia', 'ZW' => 'Zimbabwe', 'SS' => 'South Sudan', ), 'AN' => array ( 0 => 'Antarctica', 'AQ' => 'Antarctica', 'BV' => 'Bouvet Island', 'GS' => 'South Georgia and the South Sandwich Islands', 'HM' => 'Heard Island and McDonald Islands', 'TF' => 'French Southern Territories', ), 'AS' => array ( 0 => 'Asia', 'AP' => 'Asia/Pacific Region', 'AE' => 'United Arab Emirates', 'AF' => 'Afghanistan', 'AM' => 'Armenia', 'AZ' => 'Azerbaijan', 'BD' => 'Bangladesh', 'BH' => 'Bahrain', 'BN' => 'Brunei Darussalam', 'BT' => 'Bhutan', 'CC' => 'Cocos (Keeling) Islands', 'CN' => 'China', 'CX' => 'Christmas Island', 'CY' => 'Cyprus', 'GE' => 'Georgia', 'HK' => 'Hong Kong', 'ID' => 'Indonesia', 'IL' => 'Israel', 'IN' => 'India', 'IO' => 'British Indian Ocean Territory', 'IQ' => 'Iraq', 'IR' => 'Iran, Islamic Republic of', 'JO' => 'Jordan', 'JP' => 'Japan', 'KG' => 'Kyrgyzstan', 'KH' => 'Cambodia', 'KP' => 'Korea, Democratic People\'s Republic of', 'KR' => 'Korea, Republic of', 'KW' => 'Kuwait', 'KZ' => 'Kazakhstan', 'LA' => 'Lao People\'s Democratic Republic', 'LB' => 'Lebanon', 'LK' => 'Sri Lanka', 'MM' => 'Myanmar', 'MN' => 'Mongolia', 'MO' => 'Macau', 'MV' => 'Maldives', 'MY' => 'Malaysia', 'NP' => 'Nepal', 'OM' => 'Oman', 'PH' => 'Philippines', 'PK' => 'Pakistan', 'PS' => 'Palestinian Territory', 'QA' => 'Qatar', 'SA' => 'Saudi Arabia', 'SG' => 'Singapore', 'SY' => 'Syrian Arab Republic', 'TH' => 'Thailand', 'TJ' => 'Tajikistan', 'TM' => 'Turkmenistan', 'TL' => 'Timor-Leste', 'TW' => 'Taiwan', 'UZ' => 'Uzbekistan', 'VN' => 'Vietnam', 'YE' => 'Yemen', ), 'EU' => array ( 0 => 'Europe', 'AD' => 'Andorra', 'AL' => 'Albania', 'AT' => 'Austria', 'BA' => 'Bosnia and Herzegovina', 'BE' => 'Belgium', 'BG' => 'Bulgaria', 'BY' => 'Belarus', 'CH' => 'Switzerland', 'CZ' => 'Czech Republic', 'DE' => 'Germany', 'DK' => 'Denmark', 'EE' => 'Estonia', 'ES' => 'Spain', 'FI' => 'Finland', 'FO' => 'Faroe Islands', 'FR' => 'France', 'GB' => 'United Kingdom', 'GI' => 'Gibraltar', 'GR' => 'Greece', 'HR' => 'Croatia', 'HU' => 'Hungary', 'IE' => 'Ireland', 'IS' => 'Iceland', 'IT' => 'Italy', 'LI' => 'Liechtenstein', 'LT' => 'Lithuania', 'LU' => 'Luxembourg', 'LV' => 'Latvia', 'MC' => 'Monaco', 'MD' => 'Moldova, Republic of', 'MK' => 'Macedonia', 'MT' => 'Malta', 'NL' => 'Netherlands', 'NO' => 'Norway', 'PL' => 'Poland', 'PT' => 'Portugal', 'RO' => 'Romania', 'RU' => 'Russian Federation', 'SE' => 'Sweden', 'SI' => 'Slovenia', 'SJ' => 'Svalbard and Jan Mayen', 'SK' => 'Slovakia', 'SM' => 'San Marino', 'TR' => 'Turkey', 'UA' => 'Ukraine', 'VA' => 'Holy See (Vatican City State)', 'RS' => 'Serbia', 'ME' => 'Montenegro', 'AX' => 'Aland Islands', 'GG' => 'Guernsey', 'IM' => 'Isle of Man', 'JE' => 'Jersey', ), 'OC' => array ( 0 => 'Oceania', 'AS' => 'American Samoa', 'AU' => 'Australia', 'CK' => 'Cook Islands', 'FJ' => 'Fiji', 'FM' => 'Micronesia, Federated States of', 'GU' => 'Guam', 'KI' => 'Kiribati', 'MH' => 'Marshall Islands', 'MP' => 'Northern Mariana Islands', 'NC' => 'New Caledonia', 'NF' => 'Norfolk Island', 'NR' => 'Nauru', 'NU' => 'Niue', 'NZ' => 'New Zealand', 'PF' => 'French Polynesia', 'PG' => 'Papua New Guinea', 'PN' => 'Pitcairn Islands', 'PW' => 'Palau', 'SB' => 'Solomon Islands', 'TK' => 'Tokelau', 'TO' => 'Tonga', 'TV' => 'Tuvalu', 'UM' => 'United States Minor Outlying Islands', 'VU' => 'Vanuatu', 'WF' => 'Wallis and Futuna', 'WS' => 'Samoa', ), 'NA' => array ( 0 => 'North America', 'AG' => 'Antigua and Barbuda', 'AI' => 'Anguilla', 'CW' => 'Curacao', 'AW' => 'Aruba', 'BB' => 'Barbados', 'BM' => 'Bermuda', 'BS' => 'Bahamas', 'BZ' => 'Belize', 'CA' => 'Canada', 'CR' => 'Costa Rica', 'CU' => 'Cuba', 'DM' => 'Dominica', 'DO' => 'Dominican Republic', 'SX' => 'Sint Maarten (Dutch part)', 'GD' => 'Grenada', 'GL' => 'Greenland', 'GP' => 'Guadeloupe', 'GT' => 'Guatemala', 'HN' => 'Honduras', 'HT' => 'Haiti', 'JM' => 'Jamaica', 'KN' => 'Saint Kitts and Nevis', 'KY' => 'Cayman Islands', 'LC' => 'Saint Lucia', 'MQ' => 'Martinique', 'MS' => 'Montserrat', 'MX' => 'Mexico', 'NI' => 'Nicaragua', 'PA' => 'Panama', 'PM' => 'Saint Pierre and Miquelon', 'PR' => 'Puerto Rico', 'SV' => 'El Salvador', 'TC' => 'Turks and Caicos Islands', 'TT' => 'Trinidad and Tobago', 'US' => 'United States', 'VC' => 'Saint Vincent and the Grenadines', 'VG' => 'Virgin Islands, British', 'VI' => 'Virgin Islands, U.S.', 'BL' => 'Saint Barthelemy', 'MF' => 'Saint Martin', 'BQ' => 'Bonaire, Saint Eustatius and Saba', ), 'SA' => array ( 0 => 'South America', 'AR' => 'Argentina', 'BO' => 'Bolivia', 'BR' => 'Brazil', 'CL' => 'Chile', 'CO' => 'Colombia', 'EC' => 'Ecuador', 'FK' => 'Falkland Islands (Malvinas)', 'GF' => 'French Guiana', 'GY' => 'Guyana', 'PE' => 'Peru', 'PY' => 'Paraguay', 'SR' => 'Suriname', 'UY' => 'Uruguay', 'VE' => 'Venezuela', ), );

				foreach ( $_countries as $code_country => $countries ) {
					$title   = array_shift( $countries );
					$checked = ! empty( array_intersect_key( $value, $countries ) );
					?>
					<label class="continent<?php echo $disabled ? ' disabled' : ''; ?>">
						<input type="checkbox" value="continent-<?php echo $code_country; ?>"<?php checked( $checked ); ?><?php echo $attributes; ?>>
						<?php echo $title; ?>
					</label>
					<button type="button" class="hide-if-no-js expand_country"><img src="data:image/gif;base64,R0lGODlhEAAQAMQAAAAAAM/Iu3iYtcK4qPX18bDC09/b0ubm5v///9jTye3t59LMv8a+ruXh2tzYz/j4+PDw7NbRxuTh2f///wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAUUABMALAAAAAAQABAAAAVI4CSOZGmeaKqubFkIcCwUp4DcOCLUOHA/O5PgQQQ8II1gSUAAOJ0GJUkAgSgAB4lDOhJoE4DIIsAVCRaMgVpdnrxkMFprjgoBADs=" alt="+" title="<?php __( 'Expand', 'secupress' ); ?>" /></button>
					<fieldset class="hide-if-js">
						<br />
						<?php
						foreach ( $countries as $code => $title ) {
							$args['label_for'] = $args['name'] . '_' . $code;
							?>
							<div>
								&mdash; 
								<label<?php echo $disabled ? ' class="disabled"' : ''; ?>>
									<input type="checkbox" id="<?php echo $args['label_for']; ?>" name="<?php echo $name_attribute; ?>[]" value="<?php echo $code; ?>"<?php checked( isset( $value[ $code ] ) ); ?> data-code-country="<?php echo $code_country; ?>"<?php echo $attributes; ?>>
									<?php echo $title; ?>
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

			default :
				if ( method_exists( $this, $args['type'] ) ) {
					call_user_func( array( $this, $args['type'] ), $args );
				} else {
					echo 'Type manquant ou incorrect'; // ne pas traduire
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
	 */
	protected function field_button( $args ) {

		if ( ! empty( $args['label'] ) ) {
			$class  = sanitize_html_class( $args['name'] );
			$class .= ! empty( $args['style'] ) ? ' button-' . sanitize_html_class( $args['style'] ) : ' button-secondary';
			$id     = ! empty( $args['id'] )    ? ' id="' . $args['id'] . '"' : '';

			if ( ! empty( $args['url'] ) ) {
				echo '<a' . $id . ' class="secupressicon secupressicon-'. $class . ( ! empty( $args['disabled'] ) ? ' disabled' : '' ) . '" href="' . esc_url( $args['url'] ) . '">' . $args['label'] . '</a>';
			}
			else {
				echo '<button' . $id . ' class="secupressicon secupressicon-' . $class . '"' . ( ! empty( $args['disabled'] ) ? ' disabled="disabled"' : '' ) . ' type="button">' . $args['label'] . '</button>';
			}
		}

		// Helpers
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

			switch ( $helper['type'] ) {
				case 'description' :

					$description = '<p class="description desc' . $depends . $class . '">' . $helper['description'] . '</p>';
					echo apply_filters( 'secupress_help', $description, $args['name'], 'description' );
					break;

				case 'help' :

					$description = '<p class="description help' . $depends . $class . '">' . $helper['description'] . '</p>';
					echo apply_filters( 'secupress_help', $description, $args['name'], 'help' );
					break;

				case 'warning' :

					$description = '<p class="description warning' . $depends . $class . '"><strong>' . __( 'Warning: ', 'secupress' ) . '</strong>' . $helper['description'] . '</p>';
					echo apply_filters( 'secupress_help', $description, $args['name'], 'warning' );
			}
		}
	}


	// Specific fields =============================================================================

	/**
	 * Outputs the form used by the importers to accept the data to be imported.
	 *
	 * @since 1.0
	 */
	protected function import_upload_form() {
		/**
		 * Filter the maximum allowed upload size for import files.
		 *
		 * @since 1.0
		 * @since WP 2.3.0
		 *
		 * @see wp_max_upload_size()
		 *
		 * @param int $max_upload_size Allowed upload size. Default 1 MB.
		 */
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
		?>
		<p>
			<input type="file" id="upload" name="import" size="25"<?php echo $disabled; ?>/><br/>
			<label for="upload"><?php echo apply_filters( 'secupress_help', __( 'Choose a file from your computer:', 'secupress' ) . ' (' . sprintf( __( 'Maximum size: %s', 'secupress' ), $size ) . ')', 'upload', 'help' ); ?></label>
			<input type="hidden" name="max_file_size" value="<?php echo $bytes; ?>" />
		</p>
		<?php
		submit_button( __( 'Upload file and import settings', 'secupress' ), 'button', 'import', true, $disabled );
	}


	/**
	 * Outputs the export button.
	 *
	 * @since 1.0
	 */
	protected function export_form() {
		if ( secupress_is_pro() ) {
			?>
			<a href="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=secupress_export' ), 'secupress_export' ); ?>" id="export" class="button button-secondary secupressicon"><?php _e( 'Download settings', 'secupress' ); ?></a>
			<?php
		} else {
			?>
			<button class="button button-secondary" disabled="disabled"><?php _e( 'Download settings', 'secupress' ); ?></button>
			<?php
		}
	}


	/**
	 * Displays the scheduled backups module
	 *
	 * @since 1.0
	 */
	protected function scheduled_backups() {
		//// tempo
		echo '<p><em>No scheduled backups yet, create one?</em></p>';
		echo '<a href="' . wp_nonce_url( admin_url( 'admin-post.php?action=secupress_clear_alerts' ), 'secupress_clear_alerts' ) . '" class="button button-secondary">' . __( 'Clear Alerts', 'secupress' ) . '</a>';
	}


	/**
	 * Displays the alerts and add actions to delete it
	 *
	 * @since 1.0
	 */
	protected function alerts() {
		//// tempo
		echo '<p><em>No alerts found yet</em></p>';
		echo '<a href="' . wp_nonce_url( admin_url( 'admin-post.php?action=secupress_clear_alerts' ), 'secupress_clear_alerts' ) . '" class="button button-secondary">' . __( 'Clear Alerts', 'secupress' ) . '</a>';
	}


	/**
	 * Displays the banned IPs and add actions to delete it
	 *
	 * @since 1.0
	 */
	protected function banned_ips() {
		//// tempo
		echo '<p><em>No Banned IPs found yet</em></p>';
		echo '<a href="' . wp_nonce_url( admin_url( 'admin-post.php?action=secupress_clear_ips' ), 'secupress_clear_ips' ) . '" class="button button-secondary">' . __( 'Clear Banned IPs', 'secupress' ) . '</a>';
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
		<form action="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=secupress_backup_db' ), 'secupress_backup_db' ); ?>" id="form-do-db-backup" method="post">
			<div class="secupress-swal-form">
				<fieldset class="secupress-boxed-group">
					<b><?php _e( 'Unknown tables', 'secupress' ); ?></b><br>
					<?php
					foreach ( $other_tables as $table ) {
						echo '<input checked="checked" name="other_tables[]" type="checkbox"> ' . $table . '<br>';
					}
					?>
					<hr>
					<b><?php _e( 'WordPress tables (mandatory)', 'secupress' ); ?></b><br>
					<?php
					foreach ( $wp_tables as $table ) {
						echo '<input disabled="disabled" checked="checked" type="checkbox"> ' . $table . '<br>';
					}
					?>
				</fieldset>
			</div>
			<p class="submit">
				<?php
				submit_button( __( 'Backup my Database', 'secupress' ), 'secondary alignright', 'submit-backup-db', false, array(
					'data-original-i18n' => __( 'Backup my Database', 'secupress' ),
					'data-loading-i18n'  => __( 'Backuping &hellip;', 'secupress' ),
				) );
				?>
				<span class="spinner secupress-inline-spinner"></span>
			</p>
		</form>
		<?php
	}

	/**
	 * Displays the old backups
	 *
	 * @since 1.0
	 */
	protected function backup_history() {
		$backup_files = secupress_get_backup_file_list();
		$wp_tables    = secupress_get_wp_tables();
		$other_tables = secupress_get_non_wp_tables();
		?>
		<p id="secupress-no-db-backups"<?php echo $backup_files ? ' class="hidden"' : ''; ?>><em><?php _e( 'No Backups found yet, do one?', 'secupress' ); ?></em></p>
		<form id="form-delete-db-backups"<?php echo ! $backup_files ? ' class="hidden"' : ''; ?> action="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=secupress_delete_backups' ), 'secupress_delete_backups' ); ?>" method="post">
			<div class="secupress-swal-form">
				<strong id="secupress-available-backups"><?php printf( _n( '%s available Backup', '%s available Backups', count( $backup_files ), 'secupress' ), number_format_i18n( count( $backup_files ) ) ); ?></strong>
				<fieldset class="secupress-boxed-group">
					<?php array_map( 'secupress_print_backup_file_formated', array_reverse( $backup_files ) ); ?>
				</fieldset>
			</div>
			<p class="submit">
				<?php
				submit_button( __( 'Delete all Database Backups', 'secupress' ), 'secondary alignright', 'submit-delete-db-backups', false );
				?>
			</p>
		</form>
		<?php
	}


	/**
	 * Displays the files backups and the CTA to launch one
	 *
	 * @since 1.0
	 */
	protected function backup_files() {
		//// create an option so save when we launch a backup, see pro version
		$ignored_directories  = str_replace( ABSPATH, '', WP_CONTENT_DIR . '/cache/' ) . "\n";
		$ignored_directories .= str_replace( ABSPATH, '', WP_CONTENT_DIR . '/backups/' );
		?>
		<form action="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=secupress_backup_files' ), 'secupress_backup_files' ); ?>" id="form-do-files-backup" method="post">
			<div class="secupress-swal-form">
				<fieldset class="secupress-boxed-group">
					<b><?php _e( 'Do not backup the following folders', 'secupress' ); ?></b><br>
					<textarea name="ignored_directories"<?php disabled( ! secupress_is_pro() ); ?>><?php echo $ignored_directories; ?></textarea>
					<p class="description">
						<?php _e( 'One folder per line.', 'secupress' ); ?>
					</p>
				</fieldset>
			</div>
			<p class="submit">
				<?php
				$args = array(
					'data-original-i18n' => __( 'Backup my Files', 'secupress' ),
					'data-loading-i18n'  => __( 'Backuping &hellip;', 'secupress' ),
				);

				if ( ! secupress_is_pro() ) {
					$args['disabled'] = 'disabled';
				}

				submit_button( __( 'Backup my Files', 'secupress' ), 'secondary alignright', 'submit-backup-files', false, $args );
				?>
				<span class="spinner secupress-inline-spinner"></span>
			</p>
		</form>
	<?php
	}


	/**
	 * Scan the installation and search for modified files
	 *
	 * @since 1.0
	 */
	protected function file_scanner() {
		global $wp_version, $_old_files;

		if ( false !== ( $time = secupress_get_site_transient( 'secupress_toggle_file_scan' ) ) ) {
			$label = __( 'Stop task', 'secupress' );
			$class = ' working';
			$turn  = 'off';
		} else {
			$label = __( 'Search for modified files', 'secupress' );
			$class = '';
			$turn  = 'on';
		}
		$url                       = wp_nonce_url( admin_url( 'admin-post.php?action=secupress_toggle_file_scan&turn=' . $turn ), 'secupress_toggle_file_scan' );
		$orig_full_filetree        = get_option( SECUPRESS_FULL_FILETREE, false );
		$orig_wp_core_files_hashes = get_option( SECUPRESS_WP_CORE_FILES_HASHES, false )
		?>
		<p>
			<a data-original-i18n="<?php esc_attr_e( 'Search for modified files', 'secupress' ); ?>" data-loading-i18n="<?php esc_attr_e( 'Stop task', 'secupress' ); ?>" id="toggle_file_scanner" href="<?php echo $url; ?>" class="button button-secondary<?php echo $class; ?>">
				<?php echo $label; ?>
			</a>
			<span class="secupress-inline-spinner spinner"></span>
		</p>
		<?php
		if ( false === $orig_full_filetree || false === $orig_wp_core_files_hashes ) {
			?>
			<p class="description"><?php _e( 'This version of WordPress has not been scanned yet.', 'secupress' ); ?></p>
			<?php
			return;
		}

		/* Files that are not part of the WordPress installation */
		$full_filetree        = $orig_full_filetree;
		$wp_core_files_hashes = $orig_wp_core_files_hashes;

		if ( false !== $full_filetree && false !== $wp_core_files_hashes && isset( $wp_core_files_hashes[ $wp_version ]['checksums'], $full_filetree[ $wp_version ] ) ) {
			$wp_content_dir       = str_replace( realpath( ABSPATH ) . DIRECTORY_SEPARATOR, '/' , WP_CONTENT_DIR );
			$wp_core_files_hashes = $wp_core_files_hashes[ $wp_version ]['checksums'];
			// add these since it's not in the zip but depends from WordPress
			$wp_core_files_hashes[ 'wp-config.php' ] = 'wp-config.php';
			$wp_core_files_hashes[ '.htaccess' ]     = '.htaccess';
			$wp_core_files_hashes[ 'web.config' ]    = 'web.config';

			if ( is_multisite() ) {
				$wp_core_files_hashes[ $wp_content_dir . '/sunrise.php' ] = '/sunrise.php'; // add this since it's not in the zip but depends from WordPress MS
			}

			if ( defined( 'WP_CACHE' ) && WP_CACHE ) {
				$wp_core_files_hashes[ $wp_content_dir . '/advanced-cache.php' ] = '/advanced-cache.php'; // add this since it's not in the zip but depends from WordPress Cache
			}
			$wp_core_files_hashes = apply_filters( 'secupress.wp_core_files_hashes', $wp_core_files_hashes );
			$full_filetree        = $full_filetree[ $wp_version ];
			$diff_from_root_core  = array_diff_key( $full_filetree, $wp_core_files_hashes );

			if ( ! empty( $diff_from_root_core ) ) {
				?>
				<form id="form-delete-scanned-files" action="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=secupress_delete_scanned_files' ), 'secupress_delete_scanned_files' ); ?>" method="post">

				<div class="secupress-swal-form">

				<h4><?php _e( 'The followings are not files from WordPress core', 'secupress' ); ?></h4>
				<fieldset class="secupress-boxed-group small-boxed-group">
					<ul>
					<?php
						//// echo '<li><input id="diff-file-all" type=checkbox> <label for="diff-file-all">' . __( 'Select all' ) . '</label></li>'; //// uncomment when JS is ok
						foreach ( $diff_from_root_core as $diff_file => $hash ) {
							printf( '<li><input id="diff-file-%1$s" type="checkbox" name="files[]" value="%3$s"> <label for="diff-file-%1$s">%2$s</label></li>', sanitize_html_class( $diff_file ), esc_html( $diff_file ), esc_attr( $diff_file ) );
						}
					?>
					</ul>
				</fieldset>

				</div>

				<?php submit_button( __( 'Delete selected files', 'secupress' ), 'secondary alignright', 'submit-delete-files' ); ?>
				</form>
				<?php
			}
		}
		/**/

		/* Missing files from WP Core */
		$full_filetree        = $orig_full_filetree;
		$wp_core_files_hashes = $orig_wp_core_files_hashes;

		if ( false !== $full_filetree && false !== $wp_core_files_hashes && isset( $wp_core_files_hashes[ $wp_version ]['checksums'], $full_filetree[ $wp_version ] ) ) {
			$wp_core_files_hashes   = array_flip( array_filter( array_flip( $wp_core_files_hashes[ $wp_version ]['checksums'] ), 'secupress_filter_no_content' ) );
			$missing_from_root_core = array_diff_key( $wp_core_files_hashes, $full_filetree[ $wp_version ] );

			if ( ! empty( $missing_from_root_core ) ) {
				?>
				<form id="form-recover-missing-files" action="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=secupress_recover_missing_files' ), 'secupress_recover_missing_files' ); ?>" method="post">

				<div class="secupress-swal-form">

				<h4><?php _e( 'The followings are missing from WordPress core files', 'secupress' ); ?></h4>
				<fieldset class="secupress-boxed-group small-boxed-group">
					<ul>
					<?php
						//// echo '<li><input id="diff-file-all" type=checkbox> <label for="diff-file-all">' . __( 'Select all' ) . '</label></li>'; //// uncomment when JS is ok
						foreach ( $missing_from_root_core as $miss_file => $hash ) {
							printf( '<li class="secupress-actions-li"><input id="miss-file-%1$s" type="checkbox" name="files[]" value="%3$s" title="%3$s"> <label for="miss-file-%1$s" title="%3$s">%2$s</label></li>', sanitize_html_class( $miss_file ), esc_html( basename( $miss_file ) ), esc_attr( $miss_file ) );
						}
					?>
					</ul>
				</fieldset>

				</div>

				<?php submit_button( __( 'Recover selected files', 'secupress' ), 'secondary alignright', 'submit-recover-missing-files' ); ?>
				</form>
				<?php
			}
		}
		/**/

		/* old WP files */
		require_once( ABSPATH . 'wp-admin/includes/update-core.php' );

		$wp_old_files = array();
		foreach ( $_old_files as $file ) {
			if ( file_exists( ABSPATH . $file ) ) {
				$wp_old_files[ $file ] = $file;
			}
		}
		if ( ! empty( $wp_old_files ) ) {
			?>
			<form id="form-old-files" action="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=secupress_old_files' ), 'secupress_old_files' ); ?>" method="post">

			<div class="secupress-swal-form">

			<h4><?php _e( 'The followings are old WordPress core files', 'secupress' ); ?></h4>
			<fieldset class="secupress-boxed-group small-boxed-group">
				<ul>
				<?php
					//// echo '<li><input id="diff-file-all" type=checkbox> <label for="diff-file-all">' . __( 'Select all' ) . '</label></li>'; //// uncomment when JS is ok
					foreach ( $wp_old_files as $old_file ) {
						printf( '<li class="secupress-actions-li"><input id="old-file-%1$s" type="checkbox" name="files[]" value="%3$s" title="%3$s"> <label for="old-file-%1$s" title="%3$s">%2$s</label></li>', sanitize_html_class( $old_file ), esc_html( basename( $old_file ) ), esc_attr( $old_file ) );
					}
				?>
				</ul>
			</fieldset>

			</div>

			<?php submit_button( __( 'Delete selected files', 'secupress' ), 'secondary alignright', 'submit-recover-diff-files' ); ?>
			</form>
			<?php
		}
		/**/

		/* Modified WP Core files */
		$full_filetree        = $orig_full_filetree;
		$wp_core_files_hashes = $orig_wp_core_files_hashes;

		if ( false !== $full_filetree && false !== $wp_core_files_hashes && isset( $wp_core_files_hashes[ $wp_version ]['checksums'], $full_filetree[ $wp_version ] ) ) {
			$wp_core_files_hashes = apply_filters( 'secupress.wp_core_files_hashes', $wp_core_files_hashes[ $wp_version ]['checksums'] );
			$diff_from_root_core  = array();
			$full_filetree        = $full_filetree[ $wp_version ];

			foreach ($wp_core_files_hashes as $file => $hash ) {
				if ( isset( $full_filetree[ $file ] ) && ! hash_equals( $hash, $full_filetree[ $file ] ) ) {
					$diff_from_root_core[] = $file;
				}
			}
			if ( ! empty( $diff_from_root_core ) ) {
				?>
				<form id="form-recover-diff-files" action="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=secupress_recover_diff_files' ), 'secupress_recover_diff_files' ); ?>" method="post">

				<div class="secupress-swal-form">

				<h4><?php _e( 'The followings are modified WordPress core files', 'secupress' ); ?></h4>
				<fieldset class="secupress-boxed-group small-boxed-group">
					<ul>
					<?php
						//// echo '<li><input id="diff-file-all" type=checkbox> <label for="diff-file-all">' . __( 'Select all' ) . '</label></li>'; //// uncomment when JS is ok
						foreach ( $diff_from_root_core as $diff_file ) {
							$diff_url = wp_nonce_url( admin_url( 'admin-post.php?action=secupress_diff_file&file=' . $diff_file ), 'secupress_diff_file-' . $diff_file );
							printf( '<li class="secupress-actions-li"><input id="diff-file-%1$s" type="checkbox" name="files[]" value="%3$s" title="%3$s"> <label for="diff-file-%1$s" title="%3$s">%2$s</label> <span><a target="_blank" href="%4$s">See differences</a></span></li>', sanitize_html_class( $diff_file ), esc_html( basename( $diff_file ) ), esc_attr( $diff_file ), $diff_url );
						}
					?>
					</ul>
				</fieldset>

				</div>

				<?php submit_button( __( 'Recover selected files', 'secupress' ), 'secondary alignright', 'submit-recover-diff-files' ); ?>
				</form>
				<?php
			}
		}

	}

	/**
	 * Scan the installation and search for malicious files
	 *
	 * @since 1.0
	 */
	protected function virus_scanner() {
		echo '<a href="' . wp_nonce_url( admin_url( 'admin-post.php?action=secupress_get_virus_scan' ), 'secupress_get_virus_scan' ) . '" class="button button-secondary' . ( secupress_is_pro() ? '' : ' disabled' ) . '">' . __( 'Search for malicious files', 'secupress' ) . '</a>';
	}


	// Fields related ==============================================================================

	/**
	 * Output a correct name for setting fields.
	 *
	 * @since 1.0
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
		do_action( 'after_module_' . $this->modulenow . '|' . $this->pluginnow );

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
			$id    = '';
			$class = '';

			// Row ID.
			if ( ! empty( $field['args']['row_id'] ) ) {
				$id = ' id="' . esc_attr( $field['args']['row_id'] ) . '"';
			}

			// Row class.
			if ( ! empty( $field['args']['row_class'] ) ) {
				$class = $field['args']['row_class'];
			}

			if ( ! empty( $field['args']['depends'] ) ) {
				$field['args']['depends'] = explode( ' ', $field['args']['depends'] );
				$class .= ' depends-' . implode( ' depends-', $field['args']['depends'] );
			}

			if ( $class ) {
				$class = ' class="' . esc_attr( trim( $class ) ) . '"';
			}

			unset( $field['args']['row_id'], $field['args']['row_class'], $field['args']['depends'] );

			echo "<tr{$id}{$class}>";

				echo '<th scope="row">';
					// Row title.
					if ( $field['title'] ) {
						if ( ! empty( $field['args']['label_for'] ) ) {
							echo '<h4 class="hidden" id="' . sanitize_html_class( str_replace( ' ', '_', $field['title'] ) ) . '">' . $field['title'] . '</h4>';
							echo '<label for="' . esc_attr( $field['args']['label_for'] ) . '">' . $field['title'] . '</label>';
						} else {
							echo '<h4 id="' . sanitize_html_class( str_replace( ' ', '_', $field['title'] ) ) . '">' . $field['title'] . '</h4>';
						}
					}
					// Row description.
					if ( static::is_pro_feature( $field['args']['name'] ) ) {
						// If it's a pro feature, add a warning.
						$format = $field['args']['description'] ? '<br>%s' : '';
						$field['args']['description'] .= secupress_get_pro_version_string( $format );
					}
					if ( $field['args']['description'] ) {
						echo '<p class="description">' . $field['args']['description'] . '</p>';
					}
					unset( $field['args']['description'] );
				echo '</th>';

				echo '<td>';
				call_user_func( $field['callback'], $field['args'] );
				echo '</td>';

			echo '</tr>';
		}
	}


	// Main template tags ==========================================================================

	/**
	 * Print the page content. Must be extended.
	 *
	 * @since 1.0
	 */
	public function print_page() {
		die( 'Method SecuPress_Settings::print_page() must be over-ridden in a sub-class.' );
	}


	// Other template tags =========================================================================

	/**
	 * Print the current section description (because you wouldn't guess by the method's name, be thankful).
	 *
	 * @since 1.0
	 *
	 * @return (object) The class instance.
	 */
	protected function print_section_description() {
		$key = $this->modulenow . '|' . $this->sectionnow;

		if ( ! empty( $this->sections_descriptions[ $key ] ) ) {
			echo '<div class="secupress-section-description"><em>';
				echo $this->sections_descriptions[ $key ];
			echo '</em></div>';
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

		$button = get_submit_button( __( 'Save All Changes', 'secupress' ), $type, $name, false, $other_attributes );

		if ( $wrap ) {
			$button = $wrap . $button . '</p>';
		}

		if ( $echo ) {
			echo $button;
		}

		return $button;
	}


	// Utilities ===================================================================================

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


	// Includes ====================================================================================

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
