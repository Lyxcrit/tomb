$DEFAULT_FONT = "Microsoft Sans Serif"

# Creates the Main Form for each window
Function AddForm($text, $state, $width, $height, $start_pos){
    Add-Type -AssemblyName System.Windows.Forms
    $obj = New-Object system.Windows.Forms.Form
    $obj.FormBorderStyle = 'FixedDialog'
    $obj.Text = $text
    $obj.TopMost = $state
    $obj.Width = $width
    $obj.Height = $height
    $obj.StartPosition = $start_pos
    $Icon = New-Object system.drawing.icon ("$IncludeDir\includes\cpb_logo.ico")
    $obj.Icon = $Icon
    return $obj
        }
# Adds a button with specified parameters to the $parent GUI object
Function AddButton($text, $width, $height, $location_x, $location_y, $font_size, $click_func, $parent, $state){
    $obj = New-Object System.Windows.Forms.Button
    $obj.Text = $text
    $obj.Width = $width
    $obj.Height = $height
    $obj.Add_Click($click_func)
    $obj.Enabled = $state
    $obj.Location = new-object System.Drawing.Point($location_x, $location_y)
    $obj.Font = "$DEFAULT_FONT, $font_size"
    $parent.controls.Add($obj)
    return $obj
        }

# Returns a button created with specified parameters (same as above but botton is returned as object, not immediately added to GUI)
Function GetButton($text, $width, $height, $location_x, $location_y, $font_size, $click_func, $state){
    $obj = New-Object System.Windows.Forms.Button
    $obj.Text = $text
    $obj.Width = $width
    $obj.Height = $height
    $obj.Add_Click($click_func)
    $obj.Enabled = $state
    $obj.Location = new-object System.Drawing.Point($location_x, $location_y)
    $obj.Font = "$DEFAULT_FONT, $font_size"
    return $obj
        }

# Creates written text for user to better understand the current form and process 
Function AddLabel($text, $width, $height, $location_x, $location_y, $font_size, $parent, $visible){
    $obj = New-Object System.Windows.Forms.Label
    $obj.Text = $text
    $obj.Width = $width
    $obj.Height = $height
    $obj.Visible = $visible
    $obj.Location = New-Object System.Drawing.Point($location_x, $location_y)
    $obj.Font = "$DEFAULT_FONT, $font_size"
    $parent.Controls.Add($obj)
    return $obj
        }

# Add a text box for user input, used for branching, logic or user submitted options/switches 
Function AddTextBox($text, $width, $height, $location_x, $location_y, $font_size, $parent, $state, $visible){
    $obj = New-Object System.Windows.Forms.TextBox
    $obj.Text = $text
    $obj.Width = $width
    $obj.Height = $height
    $obj.Enabled = $state
    $obj.Visible = $visible
    $obj.Location = New-Object System.Drawing.Point($location_x, $location_y)
    $obj.Font = "$DEFAULT_FONT, $font_size"
    $parent.Controls.Add($obj)
    return $obj
        }

# Adds Radio button for user selections. Used for branching or user selections
Function AddRadio($text, $width, $height, $location_x, $location_y, $font_size, $click_func, $parent){
    $obj = New-Object System.Windows.Forms.RadioButton
    $obj.Text = $text
    $obj.Autosize = $true
    $obj.Width = $width
    $obj.Height = $height
    $obj.Add_Click($click_func)
    $obj.Location = new-Object System.Drawing.Point($location_x, $location_y)
    $obj.Font = "$DEFAULT_FONT, $font_size"
    $parent.Controls.Add($obj)
    return $obj
        }

# Add Checkbox for user selections, allows for multiple user selections on a single form. Used for branching based upon user selections.
Function AddCheckBox($text, $width, $height, $location_x, $location_y, $font_size, $click_func, $parent, $state){
    $obj = New-Object System.Windows.Forms.CheckBox
    $obj.Text = $text
    $obj.Autosize = $true
    $obj.Width = $width
    $obj.Height = $height 
    $obj.Add_Click($click_func)
    $obj.Location = New-Object System.Drawing.Point($location_x, $location_y)
    $obj.Font = "$DEFAULT_FONT, $font_size"
    $parent.Controls.Add($obj)
    return $obj
        }