import re

# use to capture 'element : value'
elementRegex = re.compile(r'^[\s](.+?):(.+)')
itemStartRegex = re.compile(r'.+(<custom_item).+')
itemEndRegex = re.compile(r'.+(</custom_item).+')


class NessusAudit():
    ''' convert nessus audit file python object '''

    def __init__(self, auditFile):
        self.auditFile = open(auditFile, 'r').readlines()

    def _elementList(self):
        ''' it return the element under <custom_item> .. </custom_item> '''
        elementList = []
        checkElementRegex = re.compile(r'^[\s](.+?):.+')
        for line in self.auditFile:
            checkElement = checkElementRegex.match(line)
            if checkElement:
                element = checkElement.group(1).lstrip()
                element = element.rstrip()
                # remove element contains '<'
                if not re.search(r'<', element):
                    if element not in elementList:
                        elementList.append(element)
        # new element for reference. it takes value from 'description'
        elementList.append('ref')
        return elementList

    def array(self):
        ''' this return list of dictionary contain all element'''
        array = []

        elementList = self._elementList()
        auditFileIter = iter(self.auditFile)
        for line in auditFileIter:
            if not itemStartRegex.match(line):
                continue

            tempDatastore = {}
            while True:
                item_line = next(auditFileIter)
                if itemEndRegex.match(item_line):
                    # fill empty element with value n/a
                    for element in elementList:
                        if element not in tempDatastore:
                            tempDatastore[element] = "n/a"
                    array.append(tempDatastore)
                    tempDatastore = {}  # reset datastore
                    break

                elementMatch = elementRegex.match(item_line)
                if not elementMatch:
                    continue

                element = elementMatch.group(1).lstrip().rstrip()
                value = elementMatch.group(2).lstrip().rstrip()
                if element not in elementList:
                    continue

                # This is a block of text, may be multiple lines
                if value.startswith('"'):
                    value = value.lstrip('"')
                    block_text = ""
                    current_line_text = value
                    while True:
                        if current_line_text.endswith('"'):
                            block_text += current_line_text.rstrip('"')
                            break
                        block_text += current_line_text + "\n"
                        current_line_text = next(auditFileIter).rstrip('\n')
                    value = block_text

                if element == 'description':
                    # split number and real description
                    if re.match(r'^(\d)', value):
                        ref = value.split(" ", 1)
                        tempDatastore[element] = ref[1]
                        # store the number in its keys
                        tempDatastore["ref"] = ref[0]
                    # if description contains no numbering, just
                    # push to temp datastore
                    else:
                        tempDatastore[element] = value

                else:
                    tempDatastore[element] = value

        return array
