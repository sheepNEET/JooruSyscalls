from html.parser import HTMLParser

# ------------------------ CONFIG START
INPUT_DIR = 'input/'
OUTPUT_DIR = 'output/'

BIT_DEPTH = '64' # '32' or '64'

supportedOS = \
{
	'XP' : 'Windows XP',
	'VISTA' : 'Windows Vista',
	'WIN7' : 'Windows 7',
	'WIN8' : 'Windows 8',
	'WIN81' : 'Windows 8.1'
}
supportedSP = \
{
	'XP' : [0, 1, 2, 3],
	'VISTA' : [0, 1, 2],
	'WIN7' : [0, 1],
	'WIN8' : [0],
	'WIN81' : [0]
}
tables = \
{
	'XP' : [], 'VISTA' : [], 'WIN7' : [], 'WIN8' : [], 'WIN81' : []
}
# ------------------------ CONFIG END

for osName in supportedOS:
	for _ in range(1 + max(supportedSP[osName])):
		tables[osName].append([])

class MyParser(HTMLParser):
	def __init__(self):
		super().__init__()

		self.rowNumber = (-1) # keep track of where we are
		self.colNumber = (-1)
		self.newCol = False # did we just hit a new column?

		self.colNames = [] # OS version of each column group
		self.colCounts = [] # number of service packs in each column group (may all be 1)
		self.colSP = {} # service pack lists for each column group

		self.dataList = [] # list of (syscallName, num1, num2, num3, ...) entries we read

	# print debugging
	def Diag(self):
		for name in self.colNames:
			print(name)
			if self.hasSP:
				print(self.colSP[name])
			# for syscall in self.dataList:
			# 	print(syscall)

	# get index into dataList entries (minus one) for some OS + SP
	# if no SP's in this table, return values are not unique!
	def GetOSverIndex(self, osName, osSP):
		colName = supportedOS[osName]
		colIndex = self.colNames.index(colName)
		if colIndex == -1:
			raise Exception()
		index = 0
		if colIndex > 0:
			for count in self.colCounts[:colIndex]:
				index += count
		if self.hasSP:
			spList = self.colSP[colName]
			spNumbers = sorted([int(sp[2]) for sp in spList])
			for spNum in spNumbers:
				if spNum != osSP:
					index += 1
				else:
					break
		return index

	# process data for a single OS + SP pair
	def ProcessForTarget(self, osName, osSP, target):
		index = self.GetOSverIndex(osName, osSP)
		for syscall in self.dataList:
			callName = syscall[0]
			callNumber = syscall[index+1]
			target.append([callNumber, callName])

	# process data for all OS + SP pairs
	def ProcessAllData(self):
		for osName in supportedOS:
			for osSP in supportedSP[osName]:
				target = tables[osName][osSP]
				self.ProcessForTarget(osName, osSP, target)

	def OnNewRow(self, attrs):
		self.rowNumber += 1
		self.colNumber = -1
		self.newCol = False

	def OnNewCol(self, attrs):
		self.colNumber += 1
		d = dict(attrs)

		# Height of (0,0) cell determines if the table has service packs
		if self.rowNumber == 0 and self.colNumber == 0:
			if 'rowspan' in d and int(d['rowspan']) == 2:
				self.hasSP = True
			else:
				self.hasSP = False
		# Number of service packs per OS version
		elif self.rowNumber == 0:
			if 'colspan' in d:
				self.colCounts.append(int(d['colspan']))
			else:
				self.colCounts.append(1)

		self.newCol = True

	def OnNewData(self, data):
		if not self.newCol:
			return
		else:
			self.newCol = False

		# (0,0) cell
		if self.rowNumber == 0 and self.colNumber == 0:
			pass
		# OS versions
		elif self.rowNumber == 0 and self.colNumber > 0:
			self.colNames.append(data.strip())
		# OS service packs
		elif self.rowNumber == 1 and self.hasSP:
			prevCount = len([val for key in self.colSP for val in self.colSP[key]])
			index = -1
			for q in range(len(self.colCounts)):
				index = q
				if prevCount >= self.colCounts[q]:
					prevCount -= self.colCounts[q]
				else:
					break
			if self.colNames[index] not in self.colSP:
				self.colSP[self.colNames[index]] = []
			if data.strip() == '8.0':
				# special case Windows 8
				self.colSP[self.colNames[index]].append('SP0')
			elif data.strip() != '8.1':
				self.colSP[self.colNames[index]].append(data.strip())
			else:
				# special case Windows 8.1
				self.colCounts[index] -= 1
				self.colNames.append('Windows 8.1')
				self.colCounts.append(1)
				self.colSP['Windows 8.1'] = ['SP0']
		# Syscall name
		elif self.colNumber == 0:
			self.dataList.append([])
			self.dataList[-1].append(data.strip())
		# Syscall numbers
		else:
			if data.strip() == '':
				self.dataList[-1].append(-1)
			else:
				self.dataList[-1].append(int(data.strip(), 16))

	# override HTMLParser
	def handle_starttag(self, tag, attrs):
		if tag == 'tr':
			self.OnNewRow(attrs)
		elif tag == 'td':
			self.OnNewCol(attrs)

	# override HTMLParser
	def handle_data(self, data):
		self.OnNewData(data)

def Parse(ntPath, winPath):
	ntParser = MyParser()
	winParser = MyParser()
	with open(ntPath, 'r') as f:
		ntHtml = f.read().strip()
	with open(winPath, 'r') as f:
		winHtml = f.read().strip()

	ntParser.feed(ntHtml)
	ntParser.ProcessAllData()

	winParser.feed(winHtml)
	winParser.ProcessAllData()

def DoParse():
	Parse(INPUT_DIR + 'nt{0}.html'.format(BIT_DEPTH), INPUT_DIR + 'win{0}.html'.format(BIT_DEPTH))

def OutputResults():
	with open(INPUT_DIR + 'top.h', 'r') as f:
		header = f.read() + '\n'

	tableNames = []

	outputBody = ''

	for osName in supportedOS:
		for osSP in supportedSP[osName]:
			tableName = osName + '_' + 'SP' + str(osSP) + '_table{0}'.format(BIT_DEPTH)
			tableNames.append(tableName)
			defStart = 'Table ' + tableName + ' = \n{\n'
			defEnd = '};\n'

			entries = tables[osName][osSP]
			allEntryStr = ''
			for entry in entries:
				syscallNumber = entry[0]
				syscallName = entry[1]
				entryStr = '\t{' + str(syscallNumber) + ', "' + syscallName + '"},\n'
				allEntryStr += entryStr

			outputBody += (defStart + allEntryStr + defEnd + '\n')

	tableListStr = ''
	for name in tableNames:
		tableListStr += '// ' + name + '\n'
	tableListStr += '\n'

	with open(OUTPUT_DIR + 'syscallnum{0}.h'.format(BIT_DEPTH), 'w') as f:
		f.write(header + tableListStr + outputBody)

DoParse()
OutputResults()

print('Completed')