# DISA STIG

## Document Format
```xml
<if>

    <condition type:"AND">
        <custom_item>
            system      :
            type        :
            description :
            info        :
            solution    :
            reference   :
            see_also    :
            file        :
            regex       :
            expect      :
            rpm         :
            operator    :
            required    :
        </custom_item>
    </condition>

<then>

    <report type:"PASSED">
        description     :
        info            :
        solution        :
        reference       :
        see_also        :
        value_type      :
        value_data      :
        powershell_args :
        reg_key         :
        reg_item        :
        check_type      :
        severity        :
        file            :
    </report>
    
    <report type:"WARNING">
        description     :
        info            :
        solution        :
        reference       :
        see_also        :
        value_type      :
        value_data      :
        powershell_args :
        reg_key         :
        reg_item        :
        check_type      :
        severity        :
        file            :
    </report>

    <custom_item>
        system      :
        type        :
        description :
        info        :
        solution    :
        reference   :
        see_also    :
        file        :
        regex       :
        expect      :
        rpm         :
        operator    :
        required    :
    </custom_item>

    <report type:"WARNING">
        description     :
        info            :
        solution        :
        reference       :
        see_also        :
        value_type      :
        value_data      :
        powershell_args :
        reg_key         :
        reg_item        :
        check_type      :
        severity        :
        file            :
    </report>
```


### Report Type Values

    <report type:"PASSED">
    <report type:"WARNING">

### Condition Type Values

    <condition auto:"FAILED" type:"AND">
    <condition type:"AND">
    <condition type:"OR">

### Perform Manual Check

    NOTE: Nessus has not performed this check. Please review the benchmark to ensure target compliance.

## Windows



## Linux


