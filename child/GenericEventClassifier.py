
class GenericEventClassifier:
    def __init__(self, severityConfig):
        self.author_name_high_tags = severityConfig['High']['Author-Name']
        self.event_name_high_tags = severityConfig['High']['Event-Name']
        self.author_name_medium_tags = severityConfig['Medium']['Author-Name']
        self.event_name_medium_tags = severityConfig['Medium']['Event-Name']
    
    def classify_event(self, author_name, event_name):
        if any(author in author_name for author in self.author_name_high_tags) or any(eventName in event_name for eventName in self.event_name_high_tags):
            severity = "HIGH"
        elif any(author in author_name for author in self.author_name_medium_tags) or any(eventName in event_name for eventName in self.event_name_medium_tags):
            severity = "MEDIUM"
        else:
            severity = "LOW"
        
        data = {'severity': severity,'author_name': author_name, 'event_name': event_name}
        print('[+] Generic event classifier output : ' + str(data))
        return data
        